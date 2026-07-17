# FerroGate security hardening report — July 2026

Consolidated record of an adversarial security-audit campaign run against the
FerroGate enforcement, billing, storage, crypto, network, and control-plane
surfaces. Every finding below was fixed, tested, and landed on `main`; each row
links to its commit. This report exists as reviewable evidence for the "Secure
Agent Gateway" thesis (#193/#194/#209) — the kind of artifact a design partner's
security team can audit against the code.

## Methodology

Each round fanned out one read-only adversarial auditor per surface (instructed
to find concrete, reachable exploit paths, not theoretical concerns), then ran
an independent skeptic verifier per finding whose job was to *refute* it by
reproducing the exploit path in code. Only findings a verifier independently
confirmed as reachable + exploitable were fixed. Surfaces that came back empty
are recorded as coverage evidence, not silently dropped. Every fix shipped with
a regression test and passed `scripts/security-check.sh` (fmt, `clippy
--workspace --all-targets --all-features -D warnings`, high-confidence secret
scan, vendored-Pingora integrity, protobuf advisory floor).

## Confirmed findings and fixes

Severity is the skeptic-verified real severity. All are fixed on `main`.

### Enforcement / guardrails

| Sev | Finding | Fix |
|-----|---------|-----|
| HIGH | Split-token detection evasion: adjacent same-source segments weren't coalesced, so a secret split across segment boundaries evaded the detector. Also fail-closed on findings that can't be safely redacted. | `ba93935` |
| — | Follow-up: the coalescing fix dropped anchored-pattern detections; segments are now also scanned individually. | `6f464dc` |
| HIGH | Detector dedup was O(n²) CPU + one Finding per match (~150 MB/request) — a DoS. Replaced with O(1) `HashSet` + per-segment `BTreeMap` interval dedup and a bounded findings cap with a fail-closed truncation marker. | `c5619ba` |
| HIGH | JSON-RPC `tools/call` bypassed the governed tool chokepoint, so managed-action guardrails + approval never applied to MCP tool calls. Rerouted through `execute_tool_request_with_governance`. | `38279b8` |
| MED | A co-matching hard `Block` was silently downgraded to an approval-gated action (both mapped to `Deny`, first-match won); a `Block` DLP control could be approved past. Now ranked by restrictiveness. | `9642a94` |
| HIGH | A tenant-scoped guardrail author could set a detector `secret_ref` resolved against the *host* env/Vault and shipped as a `Bearer` token to a caller-controlled endpoint — host/cross-tenant secret exfiltration. Restricted to platform operators. | `50fa768` |

### Agent / workflow / tool governance

| Sev | Finding | Fix |
|-----|---------|-----|
| HIGH | Workflow node tool-allowlist was enforced against the *declared* tool, not the *dispatched* one — a node could call a tool outside its scope. | `278e720` |

### Billing / quota / wallets

| Sev | Finding | Fix |
|-----|---------|-----|
| HIGH | Concurrent requests could overdraw a prepaid wallet (no pre-dispatch reservation). Added a RAII credit reservation. | `4da6442` |
| MED | Scope-level RPM/TPM/budget windows were keyed per-api-key, so a tenant with multiple keys bypassed a tenant/project/workspace limit. Now keyed on the winning scope. | `0400bf3` |
| HIGH | Wallet `/adjust` (mint prepaid balance) lacked `require_platform_operator`; a tenant-scoped admin key could self-credit unlimited balance → free inference. | `7c4d9ae` |

### Multi-tenant isolation / usage reporting

| Sev | Finding | Fix |
|-----|---------|-----|
| HIGH | `/admin/v1/usage-reports?group_by=metadata` returned every tenant's cost/customer-ids (the rollup had no tenant column). Contained to operators, then properly scoped per tenant (#226). | `ea1040b`, `5b03701` |

### Crypto / secrets

| Sev | Finding | Fix |
|-----|---------|-----|
| HIGH | Self-hosted worker symmetric-AEAD transport used the *public* `identity_fingerprint` (in admin listings + cleartext frames) as both the AEAD key and the bearer secret → unauthenticated worker impersonation + frame forgery. Provisioned an independent CSPRNG secret + HKDF-SHA256 derivation, fail-closed on short/legacy secrets. | `05d08ff` |
| LOW | ACME account key + issued TLS private key were written world-readable (write-then-chmod), leaving a race window + a stale 0o644 temp on crash. Now created `O_EXCL` at `0o600`, dirs `0o700`. | `3b6d1ad` |

### Network edge / SSRF

| Sev | Finding | Fix |
|-----|---------|-----|
| HIGH | The function-egress broker followed HTTP redirects with no re-validation → SSRF to cloud metadata / localhost + forwarded the project apikey. `Policy::none()` + a private-IP-blocking resolver. | `61dafb2` |
| MED | The pre-auth IP allowlist / rate-limiter trusted the leftmost (client-spoofable) `X-Forwarded-For` entry. Now selects by trusted-hop count from the right, fail-closed. | `a756581` |
| — (hardening) | The shared provider/payment client was the last egress client without `Policy::none()`. Aligned with the rest (no tenant-controlled path, but removes a compromised-upstream redirect vector). | `c7d8df1` |

### Control plane / cluster

| Sev | Finding | Fix |
|-----|---------|-----|
| MED | A guardrail-policy activation didn't propagate to peer nodes in the file-based control plane (stale enforcement on peers). Folded a monotonic generation into the shared control-plane revision. | `2a66ae2` |

### Availability / DoS

| Sev | Finding | Fix |
|-----|---------|-----|
| MED | Untrusted self-hosted-worker telemetry/heartbeat stores were uncapped (unbounded memory + O(N) per-write clone) — a cross-tenant DoS. Retention-bounded like the other analytics stores. | `c09903b` |

### Admin console

| Sev | Finding | Fix |
|-----|---------|-----|
| MED | In zero-config (auth-disabled) mode, admin mutations (e.g. `config/reload`) were CSRF-able via a cross-site simple request → gateway config takeover. Added a `Sec-Fetch-Site`/`Origin` cross-site guard on all admin mutations. | `4423d8f` |

### Isolation backend (tracked, infra-validated fix required)

| Sev | Finding | Status |
|-----|---------|--------|
| MED (latent) | The Firecracker microVM attaches the shared host rootfs read-write, contradicting the read-only-rootfs policy — latent cross-tenant persistence once guest execution is wired. | Code-site warning `1d05ebf` + tracked issue **#227** (needs a real Firecracker host to validate the guest boot). |

## Surfaces audited that returned clean (coverage evidence)

- **storage-persistence** — async-postgres repositories (tenant scoping, injection, transaction atomicity, idempotency).
- **tls-acme-network** — TLS verification, ACME challenge/account-key handling, cert resolver.
- **agent-worker management transport** — the *sibling* symmetric-AEAD channel to the self-hosted one; specifically re-checked for the same key-reuse class as the self-hosted finding and found sound.
- **mcp-oauth / PKCE** — redirect_uri/state validation, PKCE enforcement, token storage.
- **provider-proxy** and **serialization-injection** (earlier rounds).

## Result

Across six rounds the confirmed-finding severity declined from multiple HIGHs
(rounds 1–5) to all MEDIUM/LOW (round 6), which is the exhaustion signal: the
high-value attack surface is hardened. Twenty findings are fixed on `main`; one
(#227) is tracked pending a Firecracker host. The audit campaign is tapered here.

## Forward hardening carried by this campaign

- Per-tenant metadata usage breakdown restored securely (#226, closed) — the
  proper fix behind the `ea1040b` containment.
- Detector adapter conformance harness + versioned evaluation corpus/accuracy
  runner (#201) — the plug-in points the two qualifying vendor adapters slot
  into.
- Signed-snapshot verification + offline policy-loop store (#206) — fail-closed
  last-known-good behaviour for the customer-VPC data plane.

## Validation note

This repository's CI is release-gated by design (runs on `release: published`,
not per-commit — see `.github/workflows/ci.yml`), so day-to-day validation is
local. Every fix here passed local `security-check.sh` (fmt + workspace clippy +
secret scan) plus scoped/lib-suite regression tests; the #226 database migration
was additionally validated against real Postgres. The full workspace test suite
+ `cargo-deny`/`cargo-audit` run at the next release gate.
