// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-06
// description: Pre-authentication IP/CIDR allowlisting and per-source-IP
// flood throttling, applied ahead of virtual-key resolution (issue #166).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use http::HeaderMap;

/// A parsed IPv4/IPv6 CIDR range. A bare IP address (no `/n` suffix) is
/// treated as an exact match (`/32` for IPv4, `/128` for IPv6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IpCidr {
    network: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    pub(crate) fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("empty CIDR/IP entry".to_string());
        }
        let (ip_part, prefix_part) = match trimmed.split_once('/') {
            Some((ip, prefix)) => (ip, Some(prefix)),
            None => (trimmed, None),
        };
        let network: IpAddr = ip_part
            .parse()
            .map_err(|_| format!("invalid IP address: {ip_part}"))?;
        let max_prefix: u8 = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        let prefix_len = match prefix_part {
            Some(raw_prefix) => raw_prefix
                .parse::<u8>()
                .map_err(|_| format!("invalid prefix length: {raw_prefix}"))?,
            None => max_prefix,
        };
        if prefix_len > max_prefix {
            return Err(format!(
                "prefix length /{prefix_len} exceeds maximum /{max_prefix} for {network}"
            ));
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    pub(crate) fn contains(&self, candidate: &IpAddr) -> bool {
        match (self.network, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                masked_eq_u32(u32::from(network), u32::from(*candidate), self.prefix_len)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                masked_eq_u128(u128::from(network), u128::from(*candidate), self.prefix_len)
            }
            _ => false,
        }
    }
}

/// Compares the top `prefix_len` bits of two 32-bit addresses. A
/// `prefix_len` of 0 matches everything; 32 requires an exact match.
fn masked_eq_u32(a: u32, b: u32, prefix_len: u8) -> bool {
    let shift = 32u32.saturating_sub(u32::from(prefix_len));
    let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
    (a & mask) == (b & mask)
}

/// Same as [`masked_eq_u32`] but for 128-bit (IPv6) addresses.
fn masked_eq_u128(a: u128, b: u128, prefix_len: u8) -> bool {
    let shift = 128u32.saturating_sub(u32::from(prefix_len));
    let mask = u128::MAX.checked_shl(shift).unwrap_or(0);
    (a & mask) == (b & mask)
}

/// Resolves the client IP used for allowlist/rate-limit decisions: either
/// the raw TCP peer address, or (only when explicitly trusted via config) the
/// entry `trusted_proxy_hops` positions from the RIGHT of `X-Forwarded-For`,
/// falling back to `X-Real-IP`.
///
/// Trusting forwarded headers by default would let any client spoof its
/// apparent source IP, so this only consults them when `trust_forwarded_for`
/// is set (the operator has trusted reverse proxies in front and the gateway is
/// only reachable through them).
///
/// Selection is from the right, not the left: the common load balancers
/// (nginx `$proxy_add_x_forwarded_for`, AWS ALB, GCP LB, Cloudflare) *append*
/// the peer they received from, so with `H` trusted proxies in front the
/// rightmost `H` entries are proxy-authored and the `H`-th-from-right entry is
/// the real client. Everything to its left is client-supplied and therefore
/// spoofable — taking the leftmost entry (the pre-fix behavior) let a client
/// behind an appending proxy forge its apparent source IP, bypassing the
/// pre-auth allowlist and minting a fresh rate-limit window per fake IP.
/// `trusted_proxy_hops` is clamped to at least 1 whenever forwarded headers are
/// trusted.
pub(crate) fn resolve_client_ip(
    headers: &HeaderMap,
    peer_addr: Option<IpAddr>,
    trust_forwarded_for: bool,
    trusted_proxy_hops: u32,
) -> Option<IpAddr> {
    if trust_forwarded_for {
        let hops = (trusted_proxy_hops.max(1)) as usize;
        if let Some(forwarded) = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
        {
            let entries: Vec<&str> = forwarded
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .collect();
            // The client is `hops` entries from the right. If the chain is
            // shorter than the configured hop count (fewer proxies than
            // expected — a misconfiguration or a direct connection that skipped
            // the proxy fleet), do NOT fall back to a client-supplied entry;
            // drop to X-Real-IP / peer_addr below, which fail closed.
            if let Some(entry) = entries.len().checked_sub(hops).and_then(|i| entries.get(i)) {
                if let Ok(ip) = entry.parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
        if let Some(real_ip) = headers
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
        {
            return Some(real_ip);
        }
    }
    peer_addr
}

/// A pragmatic bound on how many distinct source IPs the pre-auth limiter
/// tracks at once. Once exceeded, the tracking map is cleared rather than
/// grown further, so a spoofed-source flood cannot turn the limiter itself
/// into a memory-exhaustion vector. This trades a brief window of
/// under-counting (right after a clear) for a hard memory ceiling.
const MAX_TRACKED_SOURCE_IPS: usize = 100_000;

/// Fixed-window (per-minute), per-source-IP request counter used to throttle
/// floods before any virtual-key/storage lookup happens. Deliberately
/// simpler than the per-key `ClusterCounterBackend` machinery: this is a
/// coarse, single-node, in-process flood gate, not a billing-accurate quota.
#[derive(Debug, Default)]
pub(crate) struct UnauthenticatedIpRateLimiter {
    windows: Mutex<HashMap<IpAddr, (u64, u64)>>,
}

impl UnauthenticatedIpRateLimiter {
    /// Returns `true` if `ip` is still within `limit` requests for the
    /// current `now_minute` window (a monotonically increasing minute
    /// counter, e.g. `unix_seconds / 60`).
    pub(crate) fn allow(&self, ip: IpAddr, now_minute: u64, limit: u64) -> bool {
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if windows.len() >= MAX_TRACKED_SOURCE_IPS && !windows.contains_key(&ip) {
            windows.clear();
        }
        let entry = windows.entry(ip).or_insert((now_minute, 0));
        if entry.0 != now_minute {
            *entry = (now_minute, 0);
        }
        entry.1 += 1;
        entry.1 <= limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_ipv4_as_exact_match() {
        let cidr = IpCidr::parse("203.0.113.7").unwrap();
        assert!(cidr.contains(&"203.0.113.7".parse().unwrap()));
        assert!(!cidr.contains(&"203.0.113.8".parse().unwrap()));
    }

    #[test]
    fn parses_ipv4_cidr_range() {
        let cidr = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(cidr.contains(&"10.1.2.3".parse().unwrap()));
        assert!(!cidr.contains(&"11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parses_ipv4_slash_zero_as_match_all() {
        let cidr = IpCidr::parse("0.0.0.0/0").unwrap();
        assert!(cidr.contains(&"1.2.3.4".parse().unwrap()));
        assert!(cidr.contains(&"255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn parses_ipv4_slash_32_as_exact_match() {
        let cidr = IpCidr::parse("203.0.113.7/32").unwrap();
        assert!(cidr.contains(&"203.0.113.7".parse().unwrap()));
        assert!(!cidr.contains(&"203.0.113.6".parse().unwrap()));
    }

    #[test]
    fn parses_ipv6_cidr_range() {
        let cidr = IpCidr::parse("2001:db8::/32").unwrap();
        assert!(cidr.contains(&"2001:db8::1".parse().unwrap()));
        assert!(!cidr.contains(&"2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn does_not_match_across_address_families() {
        let cidr = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(!cidr.contains(&"::1".parse().unwrap()));
    }

    #[test]
    fn rejects_invalid_ip() {
        assert!(IpCidr::parse("not-an-ip").is_err());
    }

    #[test]
    fn rejects_invalid_prefix_length() {
        assert!(IpCidr::parse("10.0.0.0/33").is_err());
        assert!(IpCidr::parse("10.0.0.0/abc").is_err());
    }

    #[test]
    fn rejects_empty_entry() {
        assert!(IpCidr::parse("").is_err());
        assert!(IpCidr::parse("   ").is_err());
    }

    fn headers_with(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                http::HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn ignores_forwarded_headers_when_not_trusted() {
        let headers = headers_with(&[("x-forwarded-for", "198.51.100.9")]);
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            resolve_client_ip(&headers, Some(peer), false, 1),
            Some(peer)
        );
    }

    #[test]
    fn uses_rightmost_untrusted_forwarded_for_entry_with_single_hop() {
        // Behind one appending proxy the chain is `<spoofable client value>,
        // <real client the proxy appended>`. With one trusted hop the real
        // client is the rightmost entry.
        let headers = headers_with(&[("x-forwarded-for", "203.0.113.7, 198.51.100.9")]);
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            resolve_client_ip(&headers, Some(peer), true, 1),
            Some("198.51.100.9".parse().unwrap())
        );
    }

    #[test]
    fn leftmost_forwarded_for_entry_cannot_spoof_an_allowlisted_source() {
        // The exploit: an attacker sends `X-Forwarded-For: 10.0.0.1` (an
        // allowlisted internal IP); the appending proxy yields
        // `10.0.0.1, <attacker_ip>`. The old leftmost selection returned the
        // spoofed 10.0.0.1; the fix returns the attacker's real appended IP.
        let headers = headers_with(&[("x-forwarded-for", "10.0.0.1, 203.0.113.66")]);
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let resolved = resolve_client_ip(&headers, Some(peer), true, 1).unwrap();
        assert_eq!(resolved, "203.0.113.66".parse::<IpAddr>().unwrap());
        assert_ne!(resolved, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn selects_client_by_hop_count_through_a_proxy_chain() {
        // Two trusted proxies: `<spoofable>, <client>, <proxy1>`. With two hops
        // the client is two entries from the right.
        let headers = headers_with(&[("x-forwarded-for", "203.0.113.7, 198.51.100.9, 192.0.2.10")]);
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            resolve_client_ip(&headers, Some(peer), true, 2),
            Some("198.51.100.9".parse().unwrap())
        );
    }

    #[test]
    fn falls_back_when_chain_is_shorter_than_the_hop_count() {
        // Fewer entries than configured hops (a direct connection that skipped
        // the proxy fleet): do NOT trust a client-supplied entry -- fall back to
        // X-Real-IP / peer.
        let headers = headers_with(&[
            ("x-forwarded-for", "203.0.113.7"),
            ("x-real-ip", "198.51.100.9"),
        ]);
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            resolve_client_ip(&headers, Some(peer), true, 2),
            Some("198.51.100.9".parse().unwrap())
        );
        let peer_only = headers_with(&[("x-forwarded-for", "203.0.113.7")]);
        assert_eq!(
            resolve_client_ip(&peer_only, Some(peer), true, 2),
            Some(peer)
        );
    }

    #[test]
    fn falls_back_to_real_ip_header_when_trusted() {
        let headers = headers_with(&[("x-real-ip", "198.51.100.9")]);
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            resolve_client_ip(&headers, Some(peer), true, 1),
            Some("198.51.100.9".parse().unwrap())
        );
    }

    #[test]
    fn falls_back_to_peer_addr_when_no_forwarded_headers_present() {
        let headers = HeaderMap::new();
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(resolve_client_ip(&headers, Some(peer), true, 1), Some(peer));
    }

    #[test]
    fn rate_limiter_allows_up_to_limit_then_denies() {
        let limiter = UnauthenticatedIpRateLimiter::default();
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        for _ in 0..5 {
            assert!(limiter.allow(ip, 100, 5));
        }
        assert!(!limiter.allow(ip, 100, 5));
    }

    #[test]
    fn rate_limiter_resets_on_new_window() {
        let limiter = UnauthenticatedIpRateLimiter::default();
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        for _ in 0..5 {
            assert!(limiter.allow(ip, 100, 5));
        }
        assert!(!limiter.allow(ip, 100, 5));
        assert!(limiter.allow(ip, 101, 5));
    }

    #[test]
    fn rate_limiter_tracks_sources_independently() {
        let limiter = UnauthenticatedIpRateLimiter::default();
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let b: IpAddr = "203.0.113.2".parse().unwrap();
        for _ in 0..5 {
            assert!(limiter.allow(a, 100, 5));
        }
        assert!(!limiter.allow(a, 100, 5));
        assert!(limiter.allow(b, 100, 5));
    }
}
