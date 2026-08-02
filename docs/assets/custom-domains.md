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

## 6. The certificate half — Cloudflare for SaaS

A Worker only sees a request for `docs.acme.com` if **Cloudflare terminated TLS
for that hostname and routed it to this Worker.** Two mechanisms do that, and
FerroGate picked one:

| | Workers Custom Domains | **Cloudflare for SaaS custom hostnames** |
|---|---|---|
| where the hostname lives | a zone in **your** account | the **tenant's** zone |
| who controls the DNS | you do | the tenant, CNAMEd at your fallback origin |
| certificate | an Advanced Certificate on **your** zone, for the target hostname | **one per hostname**, with its own DCV |
| per-hostname status | reachable — the domain row carries `cert_id`, then a second call to the certificate API | `status` + `ssl.status` on the row already fetched |

**Custom hostnames, and here is why.** FerroGate is multi-tenant and a tenant
keeps its own DNS — `acme.com` is not, and must not become, a zone in our
account. **You cannot create a Workers Custom Domain on a zone you do not own**,
so it would require every customer to hand us their zone. That argument decides
it on its own, and it is the only one this choice rests on.

Not the reason, stated so nobody re-opens this on a false premise: Workers
Custom Domains are *not* status-blind. Creating one also generates an Advanced
Certificate on the target zone for the target hostname, and
`GET /accounts/{account_id}/workers/domains/{domain_id}` returns a `cert_id`
("ID of the TLS certificate issued for the domain"). Per-hostname certificate
state exists there and could feed this endpoint — at the price of a second call
to a different certificate API, on a zone we would have to own. The
`custom_hostnames` row simply carries it in the answer we already have.

**What it costs.** Cloudflare for SaaS is a paid entitlement billed per active
custom hostname. It needs a dedicated fallback-origin zone in your account, a
DNS record on it for tenants to CNAME at, a Worker route covering that origin,
and an API token carrying the **zone-level** `SSL and Certificates: Edit`
permission group. An otherwise-complete *account* token cannot reach
`/zones/.../custom_hostnames`.

### 6.1 The client

`packages/cloudflare/src/custom-hostnames.ts` (`CustomHostnamesClient`) — the
same shape as the package's D1 and R2 modules: one `CloudflareClient`, one
envelope decoder, one error taxonomy, one retry policy. Three behaviours are
deliberately *not* the same as `r2.ts` and each is argued in that file's header:

* a `1406` duplicate is **reconciled against our own zone**, never absorbed into
  success. An R2 bucket name is unique per account so its duplicate code proves
  the bucket is ours; a custom hostname is unique across *all* of Cloudflare, so
  `1406` may mean another account holds it and no certificate will ever issue;
* `?hostname=` is a **contains** filter, so the exact-equality re-check is
  load-bearing — without it `docs.acme.com` can be answered by a row for
  `docs.acme.com.attacker.test`;
* the status fold never guesses `active`.

### 6.2 The states, and what an operator does about each

`GET /admin/v1/site-domains/{hostname}` answers with `certificate_status` plus a
`certificate` object carrying Cloudflare's raw `hostname_status` / `ssl_status`
and any `validation_records`. It is an enum and not a boolean because five of
these mean "the domain does not work yet" and each names a **different** action:

| `certificate_status` | what is true | what you do |
|---|---|---|
| `unconfigured` | this deployment binds no certificate backend | FerroGate did not look — a fact about the deployment, not the domain |
| `not_provisioned` | no custom-hostname row exists | provision it; the domain cannot serve |
| `unavailable` | the backend could not answer | retry; the state is unknown and is **not** folded into anything |
| `pending_validation` | Cloudflare awaits its DCV record | publish `certificate.validation_records`; **requests fail TLS until then** |
| `provisioning` | issuance/deployment in flight | wait |
| `issued_not_routing` | certificate live, hostname not routing | fix the tenant's CNAME — TLS is not the problem |
| `active` | issued **and** routing | nothing |
| `timed_out` | Cloudflare stopped retrying | fix DNS, restart validation |
| `expired` | certificate lapsed | re-validate |
| `blocked` | Cloudflare refused the hostname | it collides elsewhere on Cloudflare; support |
| `inactive` | deleted / deleting / deactivating | re-provision |
| `unknown` | a status this platform does not classify | read the raw pair |

The `LIST` operation deliberately omits all of this: N bindings would be N
outbound Cloudflare calls per page.

### 6.3 The certificate is independent of the ownership proof

They answer different questions and neither implies the other:

* live certificate, no FerroGate proof → the request **arrives and is refused
  421**;
* live proof, no certificate → the request **never arrives** at all.

So `certificate_status` sits *beside* `verified`, never merged into it, and
nothing on the serving path reads it. A single boolean would hide exactly the
case an operator is debugging.

### 6.4 What this repository still cannot prove

`workerd` under vitest has **no TLS terminator, no zone and no certificate
authority.** So:

* **no test here has ever called Cloudflare.** The client is exercised against a
  scripted transport; the admin endpoint is exercised against a deterministic
  backend fed Cloudflare's own result shape. Both prove the request shapes, the
  pagination walk, the duplicate reconcile, the fold and the surfacing — and
  **none of them is evidence that Cloudflare answers this way.** The response
  shapes and both status enums are taken from Cloudflare's published schema.
* **TLS termination and SNI are untested and untestable here.** No assertion in
  this tree should be read as saying a certificate works.
* **Provisioning is not yet driven automatically.** `ensureCustomHostname` is
  written, typed and tested, and the admin GET reads state through the same
  client — but no `POST /admin/v1/site-domains` handler calls it, because
  creating a billable Cloudflare resource on a tenant-triggered admin write is
  an operator decision that needs its own issue (rate limiting, cleanup on
  unbind, what happens when the entitlement is absent). Until then the operator
  provisions the hostname out of band and this endpoint reports its state.

### 6.5 Turning it on

```toml
# apps/control-plane — not committed values; see wrangler.toml's own comment
SITE_DOMAIN_CERTIFICATES  = "cloudflare_for_saas"
SITE_DOMAIN_CF_ZONE_ID    = "<the fallback-origin zone in YOUR account>"
SITE_DOMAIN_CF_ACCOUNT_ID = "<that zone's account>"
```

```sh
wrangler secret put SITE_DOMAIN_CF_API_TOKEN --name ferrogate-control-plane
```

Absent, the default is `unconfigured`: no outbound call is made, so a deployment
does not acquire Cloudflare traffic merely by upgrading.
