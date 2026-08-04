# CLI Catalog Management Design

**Issue:** #816

## Goal

Add first-class `ferrogate provider` and `ferrogate model` commands for the
tenant provider-channel, logical-model, and model-offering catalog. The CLI is
an Admin API client only: it never opens D1 and it does not reproduce the
control-plane catalog validator.

## Chosen Shape

The command tree follows the issue examples:

```text
ferrogate provider list|add|show|update|rm
ferrogate provider import --from-env
ferrogate model list|add|show|update|rm
ferrogate model offering add|ls|show|update|rm
```

All leaves accept the existing control-plane context flags (`--endpoint`,
`--token-env`, `--token-stdin`, `--tenant`, `--timeout-millis`, `--output`,
and `--non-interactive`) plus `--json`. `--json` is a shorthand for JSON
output and conflicts with `--output`; default output is a human-readable table.
Existing `ctl catalog models/providers` remains available.

## Assumptions

1. A provider channel's CLI name is also its Admin API id. `provider add`
   sends `id=name`, which makes the issue's `show <name>` and `rm <name>`
   deterministic without a second name lookup.
2. A logical model's CLI name is also its Admin API id for the same reason.
3. The Admin API's nested offering route requires a model id. Offering commands
   accept `<model> <offering>` where both are supplied; the one-argument
   `show`, `update`, and `rm` forms resolve an offering id by listing models
   and their offerings through the Admin API. No D1 shortcut is introduced.
4. `model show` performs `GET /admin/v1/models/{id}` and
   `GET /admin/v1/models/{id}/offerings`, then emits one combined document.
   Its table is the money view: model metadata followed by one row per
   offering with provider, upstream model, role, and all price columns.
5. `provider import --from-env` parses only enough JSON structure to map
   `GATEWAY_PROVIDERS` and `GATEWAY_MODELS`; field and catalog validity remains
   the Admin API's responsibility. Provider/model ids are deterministic names,
   and offerings use deterministic ids plus matching by existing provider,
   upstream model, and role so a second import creates no duplicates.
6. Env model routes are imported as one primary offering, zero or more
   fallbacks, and optional canary/shadow offerings. Their route price and
   capability fields are copied to the offering body; model metadata remains
   on the model body.

## Security and Errors

`--api-key-var` is a binding/reference name, never a credential value. The
client rejects key-shaped `sk-*` values before resolving a request context or
sending any HTTP request, without echoing the value. The same guard runs over
all imported provider references before import makes its initial list calls.
Successful provider responses are rendered from server data, which contains
only `has_api_key`/metadata; diagnostics redact credential-shaped field names.
Non-2xx responses use the existing transport classification, so the server's
code and message are printed on stderr and the established non-zero exit class
is preserved, including a clear HTTP 409 conflict.

## Testing

CLI tests cover request paths/bodies, table and JSON output, model-show price
rendering, two-request composition, credential rejection with zero requests,
server error propagation, offering-id resolution, env import mapping, and
idempotent repeated import. The control-plane suite remains the end-to-end
proof of the already-landed Admin CRUD/409 behavior; the CLI suite exercises
that contract through its real command dispatch and in-memory transport. A
mutation check changes an offering price fixture and asserts the money view
changes, and a deliberate credential-guard mutation must make its test fail.

