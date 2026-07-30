# pay.sh x402 sidecar — inbound fixed-price route (issue #356)

Sandbox/local deployment for charging an external agent to call **one**
fixed-price FerroGate-hosted API.

```
external x402 client ──▶ pay-sidecar ──▶ ferrogate-paid (PRIVATE)
                                          ferrogate-admin (separate network)
```

| File | What it is | Checked by |
|---|---|---|
| `docker-compose.yaml` | The topology. The network layout *is* the isolation claim | manual boundary checks below |
| `ferrogate-x402-inbound.toml` | FerroGate's side: fixed price, sidecar admission, claim bounds | **committed test** — `crates/ferrogate-config/src/x402_inbound_test.rs` loads this exact file, validates it, and resolves it |
| `ferrogate-x402-admin.toml` | The control-plane service's config: its listener and the gateway it proxies to | **committed test** — same file, loaded as a full `Config` |
| `pay-server.yaml` | The sidecar spec | **nothing** — see the SCHEMA STATUS banner in the file |

> ## ⚠️ The FerroGate gate is not wired into the request path
>
> This slice ships the inbound x402 decision gate as a **library with no
> caller**. Bringing this topology up gives you the network isolation and
> nothing else: the priced route is served **unmonetized**, an unpaid call is
> **not** answered with 402, and the sidecar credential is **not** verified on
> the upstream hop. See "Runtime wiring is NOT landed" in
> `docs/x402-inbound-sidecar.md`, tracked in #625. Do not deploy this expecting
> to be paid.

## Run it

```bash
export FERROGATE_X402_INBOUND_SIDECAR_SECRET="$(openssl rand -hex 24)"
export FERROGATE_ADMIN_JWT_SECRET="$(openssl rand -hex 32)"
export PAY_RECIPIENT=<devnet USDC wallet>
docker compose up -d
```

### Variable expansion in `pay-server.yaml`

`pay-server.yaml` is bind-mounted read-only, and **Docker Compose does not
interpolate variables inside a mounted file's contents** — only inside
`docker-compose.yaml` itself. Whether the `${PAY_NETWORK}` / `${PAY_RECIPIENT}` /
`${PAY_FACILITATOR_URL}` / `${PAY_UPSTREAM_CREDENTIAL}` placeholders are expanded
therefore depends entirely on whether `pay server` performs its own environment
substitution, which **this slice has not verified against a pinned `pay`
release**.

If it does not, pre-render the file before starting:

```bash
envsubst < pay-server.yaml > pay-server.rendered.yaml   # then mount the rendered file
```

Two consequences of getting this wrong, so check rather than assume:

- an unexpanded `${PAY_UPSTREAM_CREDENTIAL}` is presented literally and the
  upstream refuses the hop with `CredentialMismatch` (403) — noisy, self-evident;
- an unexpanded (or otherwise constant) `${PAY_REQUEST_ID}` gives **every** call
  the same sidecar request id. That is silent, and it is the dangerous one: the
  sidecar request id is the forward-once ownership key, so a constant value makes
  every distinct paid call look like a retry of the first. Confirm it differs
  per call before any non-sandbox use.

Devnet by default. Mainnet is a separate, explicit operator decision — this
slice has no production merchant path (see the Durability section of
`docs/x402-inbound-sidecar.md`).

## Checks that will pass once the gate is wired in

**These two do NOT hold on this code** — they describe the intended end state,
not current behaviour. Until the runtime wiring lands (#625), the first returns
the handler's own response instead of a 402, and the second pays for something
that was never gated.

```bash
# Unpaid call -> 402 + PAYMENT-REQUIRED
curl -i -X POST http://localhost:8402/v1/priced/report

# Paid call, devnet sandbox, no mainnet funds
pay --sandbox curl -X POST http://localhost:8402/v1/priced/report
```

## Checks that must FAIL

These are the security claims. Run them; do not trust the comments.

```bash
# The sidecar has no route to the admin service (no shared network)
docker compose exec pay-sidecar getent hosts ferrogate-admin

# The protected upstream publishes no port
curl -i --max-time 2 http://localhost:8080/v1/priced/report

# Even from inside paid-upstream, an uncredentialed call is refused with 403
# NOTE: this one is a gate property, so it only holds once the wiring lands.
docker compose exec pay-sidecar \
  wget -qO- --header 'x-ferrogate-sidecar-request-id: probe' \
  http://ferrogate-paid:8080/v1/priced/report
```

The first two are Docker networking properties and hold today. Note that a
`docker compose exec ... wget` also "fails" when the image ships no `wget`, so
treat the DNS check (`getent hosts`, glibc-only) as the load-bearing one.

**None of the above has been executed in CI for this slice.** They need a pinned
`pay` image and a devnet wallet. What *is* mechanically checked is the FerroGate
half: admission, settlement verification and forward-once are covered by unit and
property tests in `ferrogate-billing`, and this directory's TOML is loaded by a
committed config test.

## Rotating the sidecar credential

1. Set `FERROGATE_X402_INBOUND_SIDECAR_SECRET_PREVIOUS` to the current secret and
   uncomment `rotating_out_secret_env` in the TOML. Restart `ferrogate-paid`.
2. Set `FERROGATE_X402_INBOUND_SIDECAR_SECRET` to the new secret everywhere and
   restart both services.
3. Watch the `sidecar_credential` evidence field. Retire step 1 only once it has
   read `active` for a full deployment window — a `rotating_out` reading means
   something is still presenting the old secret.

The config refuses a rotation where both variables name the same value, so a
rotation that changes nothing cannot look in progress.
