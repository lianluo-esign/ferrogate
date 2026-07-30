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
| `pay-server.yaml` | The sidecar spec | **nothing** — see the SCHEMA STATUS banner in the file |

## Run it

```bash
export FERROGATE_X402_INBOUND_SIDECAR_SECRET="$(openssl rand -hex 24)"
export FERROGATE_ADMIN_JWT_SECRET="$(openssl rand -hex 32)"
export PAY_RECIPIENT=<devnet USDC wallet>
docker compose up -d
```

Devnet by default. Mainnet is a separate, explicit operator decision — this
slice has no production merchant path (see the Durability section of
`docs/x402-inbound-sidecar.md`).

## Checks that must pass

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
docker compose exec pay-sidecar \
  wget -qO- --header 'x-ferrogate-sidecar-request-id: probe' \
  http://ferrogate-paid:8080/v1/priced/report
```

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
