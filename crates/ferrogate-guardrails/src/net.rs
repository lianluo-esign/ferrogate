// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! SSRF-safe networking for detector egress: DNS resolution filtering and
//! the private/reserved address denylist.

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, Copy)]
pub(crate) struct GuardrailDnsResolver {
    pub(crate) allow_private_network: bool,
}

impl Resolve for GuardrailDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let allow_private_network = self.allow_private_network;
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((host.as_str(), 0)).await.map_err(
                |_| -> Box<dyn std::error::Error + Send + Sync> {
                    Box::new(std::io::Error::other(
                        "guardrail detector DNS resolution failed",
                    ))
                },
            )?;
            let filtered = filter_resolved_detector_addresses(addresses, allow_private_network);
            if filtered.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "guardrail detector DNS resolved only disallowed addresses",
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(filtered.into_iter()) as Addrs)
        })
    }
}

pub(crate) fn filter_resolved_detector_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
    allow_private_network: bool,
) -> Vec<SocketAddr> {
    addresses
        .into_iter()
        .filter(|address| allow_private_network || !is_disallowed_detector_ip(address.ip()))
        .collect()
}

pub fn is_disallowed_detector_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_disallowed_v4(ip),
        IpAddr::V6(ip) => is_disallowed_v6(ip),
    }
}

fn is_disallowed_v4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0)
        || (a == 198 && (18..=19).contains(&b))
        || a >= 240
}

fn is_disallowed_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_disallowed_v4(mapped);
    }
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
}
