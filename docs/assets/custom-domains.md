# Verified custom domains for static sites

*Issue #738. Companion to the `/sites/{site}/{path}` serve mode (#737) and the
DNS-TXT ownership challenge (#488/#576).*

A tenant that has published a `static_site` bundle can serve it on its own
hostname — `docs.acme.com` instead of `…/sites/acme/`. This document is the
operator runbook, the security argument, and an explicit statement of the part
this repository **cannot** exercise offline.

---

## 1. The shape of it

```
  request on docs.acme.com
        │
        ▼
  site_domains(hostname)            ──►  no row?  request routes normally
        │  JOIN ON hostname AND tenant_id
        ▼
  site_domain_verifications(tenant_id, hostname)
        │
        ├─ no live proof ────────────►  421 site_domain_not_active
        │
        ▼
  (tenant, slug)  ──►  SiteServer.serve  ◄──  /sites/{slug}/{path}
                            │
                            ▼
                   AssetService.pullAsset → #resolveArtifact
```

**There is one resolution path.** A hostname produces nothing but a
`(tenant, slug)` pair; the channel, the semver ladder, yank, the withholding of
`pending_scan` / `quarantined` versions, the egress budget, the `asset.pull`
audit row and the cache directives are the same code `/sites/*` runs. A site
yanked on its slug is yanked on its custom domain, in the same call.

---

## 2. How a hostname becomes servable

1. **Bind.** `POST /admin/v1/site-domains {"hostname": "...", "site_id": "..."}`.
   This records INTENT only. It serves nothing.
2. **Ask for the challenge.** `POST /admin/v1/site-domains/{hostname}/verify`
   answers `409 site_domain_challenge_issued` with the record to publish. It
   does not verify — nothing was checked, so a 200 would be a lie.
3. **Publish the TXT record.**
   `_ferrogate-challenge.<hostname>  TXT  "ferrogate-site-verification=<digest>"`
   where the digest is SHA-256 over the length-prefixed
   `(domain-tag, tenant_id, hostname, token)` tuple. The token is 128 random
   bits FerroGate minted and never published.
4. **Verify again.** On a match the tenant takes the serving claim
   (`site_domains`) and a 90-day verification deadline starts.
5. **Point the DNS and provision the certificate** — see §5. Until Cloudflare
   routes the hostname to the Worker, nothing above matters.

Re-verification is required every 90 days; an unredeemed challenge token
expires after 7. Both are applied at READ time, so neither depends on a sweeper.

### Why the proof cannot be spoofed

The digest is bound to ONE tenant and ONE hostname. Tenant B standing in front
of A's published record learns nothing usable: B's own challenge row holds a
different token, so the value B must publish is a different digest, and the
token is not recoverable from the digest. Publishing the record therefore
requires control of the zone's authoritative DNS, which is what owning a domain
means.

`unavailable` is never `verified`. A resolver that cannot answer is a 503 and
the binding keeps whatever state it had; the DEFAULT resolver is the one that
can never answer, so a deployment that has not configured DNS verification
cannot accidentally verify anything.

---

## 3. One domain, one owner

`site_domains.hostname` is a PRIMARY KEY. The claim is taken by a single
guarded statement —

```sql
INSERT INTO site_domains (...) VALUES (...)
ON CONFLICT (hostname) DO UPDATE SET ...
WHERE site_domains.tenant_id = excluded.tenant_id
```

— so `changes() > 0` IS the grant: the first tenant to complete a DNS proof
wins, a re-verification by the same tenant renews, and any other tenant is
refused with `site domain hostname is already claimed by another tenant`. The
loser is told, rather than left with a binding that quietly never serves.

A second, independent fence sits in the gateway: the operator's `GATEWAY_SITES`
entry for the slug must belong to the same tenant as the domain, or the request
is refused with the uniform `site_not_found`. Serving either side of a
disagreement would put one tenant's bytes on the other's authority.

**Known divergence, recorded rather than hidden:** `control_plane_resources`
keys the `site-domains` DOCUMENT on the hostname alone, so the second tenant to
BIND is already refused with a 409 and cannot hold a pending challenge — which
the `site_domain_verifications` schema note says should be possible so that a
squatter cannot block the real owner. That is pre-existing behaviour of the
generic CRUD store; #738 did not change it, and
`apps/control-plane/test/site-domain-projection.test.ts` asserts it out loud.

---

## 4. What stops serving, and when

| event | effect | bound by |
|---|---|---|
| verification passes its 90-day deadline | refused | **immediately** — recomputed per request from the cached deadline |
| challenge token passes its 7-day TTL | refused | immediately |
| `DELETE /admin/v1/site-domains/{hostname}` | refused, then routed normally | ≤ `SITE_DOMAIN_CACHE_TTL_SECONDS` (60s) per isolate |
| the tenant re-verifies / re-binds | serves | ≤ 60s per isolate |
| bundle yanked, quarantined, or withheld | `404 site_not_found` | immediately |

The 60s bound is a per-isolate cache of the `site_domains` READ. It bounds row
changes only; expiry is computed from `nowUnix` against the cached deadlines on
every request, so a verification that lapses mid-window stops serving on the
very next request.

An inactive authority answers **`421 Misdirected Request`** with
`site_domain_not_active`, on every path including `/healthz` — RFC 9110
§15.5.20, "the request was directed at a server that is not able to produce a
response for the combination of scheme and authority", which is exactly what
has happened. Falling through to normal routing would make "verified" and "not
verified" indistinguishable to whoever pointed the DNS, which is the state a
domain-takeover primitive needs to go unnoticed.

---

## 5. Access, and what a custom domain does NOT grant

A custom domain contributes a slug and a proven tenant. **It does not make a
site public.** The binding synthesized for a slug with no `GATEWAY_SITES` entry
is private and pinned to the domain's own tenant, so a verified hostname
answers `401 missing_api_key` until the operator opts the site in with

```json
GATEWAY_SITES = {"acme": {"tenant_id": "…", "asset_name": "docs",
                          "channel": "stable", "anonymous": true}}
```

That is deliberate. #737 made anonymous serving an operator decision, per site
AND per channel, and a DNS proof is a claim about a hostname — not the
operator's decision to publish a bundle to the entire internet. Letting the
domain imply anonymity would be a second, weaker path to the same thing.

Every read on a custom domain — anonymous included — spends the OWNING tenant's
egress budget, trips the same download-RPM window, and writes the same
`asset.pull` audit row as a read of `/sites/{slug}/`. There is no unmetered
path.

Because the authority belongs to the tenant, the gateway's own surface is NOT
served on it: `/healthz`, `/version`, `/metrics` and `/v1/**` on a custom
domain are paths inside the tenant's document tree.

---

## 6. What this repository cannot prove — TLS, SNI and provisioning

A Worker only sees a request for `docs.acme.com` if **Cloudflare terminated TLS
for that hostname and routed it to this Worker.** Two deploy-time mechanisms do
that:

* **Workers Custom Domains** — the hostname is on a zone in your own Cloudflare
  account; the certificate is managed for you. Suitable when the operator owns
  the zones.
* **Cloudflare for SaaS custom hostnames** (`/zones/{zone}/custom_hostnames`) —
  the hostname is on the TENANT's zone, pointed at your fallback origin by
  CNAME, and Cloudflare issues a certificate per hostname after its own
  validation (HTTP or TXT, separate from the ownership challenge above).
  Suitable for a multi-tenant product, which is this one.

**Neither is implemented in this tree, and nothing here tests them.** `workerd`
under vitest has no TLS terminator, no zone and no certificate authority, so a
test asserting "the certificate is active" could only assert against a stub of
our own writing and would be evidence of nothing. The honest position is that
#738 delivers everything downstream of the `Host` header — the ownership proof,
the claim, the fences, the refusals and the serve path — and that the
provisioning call and the `certificate_status` field on
`GET /admin/v1/site-domains/{hostname}` are still open. Until they land, an
operator provisions the hostname out of band (dashboard or API) and reads its
certificate state there.

Two consequences worth stating for whoever picks that up:

* The certificate state and the ownership proof are **independent**. A hostname
  can have a live certificate and no FerroGate proof (it is refused with 421),
  or a live proof and no certificate (the request never arrives). Surfacing them
  as one boolean would hide exactly the case an operator is debugging.
* A `custom_hostnames` create is an outbound call to the Cloudflare API with an
  account-scoped token. It belongs behind `@ferrogate/cloudflare`'s client, on
  the control plane, and it must be idempotent per hostname — the admin API is
  retried, and a duplicate create is a 409 from Cloudflare rather than a second
  certificate.
