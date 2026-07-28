<!--
Token4AI Cloud Attribution
Developed by the commercial cloud service company represented by https://token4ai.cloud.
Author: jamesduan (X: https://x.com/JamesDuanL)
description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
-->

# FerroGate CLI migration notes

Factual mapping from the legacy `admin-api` command/flag naming to the current
`ferrogate` CLI surface. It covers the two renames that touched operator muscle
memory (issue #359's Control Plane API promotion) and clarifies how the legacy
direct-to-gateway commands relate to the newer generic Control Plane API client
tree (`ferrogate ctl <group> <verb>`, issues #361-#365).

For the full, generated command list see [`cli-reference.md`](cli-reference.md).

## 1. `admin-api` → `control-api` (issue #359)

The standalone Admin API service was promoted to the **FerroGate Control Plane
API**. The command and its config section were renamed; the old names remain as
deprecated aliases during the migration window and behave identically.

### Command

| Legacy (deprecated alias)      | Current (canonical)              |
| ------------------------------ | -------------------------------- |
| `ferrogate admin-api serve`    | `ferrogate control-api serve`    |

- `ferrogate admin-api serve` still runs the same Control Plane API service, but
  first logs an actionable deprecation warning nudging you to `control-api`.
- Both commands take the identical `-c, --config <CONFIG>` flag
  (`FERROGATE_CONFIG`) and load the same config file.

### Config section

| Legacy (deprecated alias) | Current (canonical) |
| ------------------------- | ------------------- |
| `[admin_api]`             | `[control_api]`     |

- An `[admin_api]`-only file still loads (it maps 1:1 onto `[control_api]`) and
  logs a rename notice.
- A `[control_api]`-only file loads with no warning.
- Setting **both** sections is rejected with an error — they configure the same
  service, so keep only one. Prefer `[control_api]`.
- The field names inside the section are unchanged; only the section header was
  renamed.

### HTTP surface

The wire contract is unchanged: the Control Plane API service still terminates
and proxies the path-compatible `/admin/v1/*` (and `/v1/assets/*`) surface to
the configured gateway. No client that spoke to `/admin/v1/*` needs to change
paths for this rename. (A newer `/control/v1` URI alias normalizes onto the same
`/admin/v1` routes; see the control-plane API contract docs.)

## 2. Direct-to-gateway `assets` / `plans` vs. the Control Plane API client

The pre-existing top-level gateway commands are **preserved unchanged** — this
slice adds no rename to them:

| Command                        | Purpose                                             | Connection flags                         |
| ------------------------------ | --------------------------------------------------- | ---------------------------------------- |
| `ferrogate assets push/pull/list/delete` | Manage static assets over `/v1/assets/*` | `--gateway-url` / `--api-key` (env: `FERROGATE_GATEWAY_URL` / `FERROGATE_API_KEY`) |
| `ferrogate plans create/list/assign`     | Manage sellable subscription plans        | `--gateway-url` / `--api-key`            |

Issues #361-#365 added a **separate** generic Control Plane API client mounted
under `ferrogate ctl <group> <verb>`, including resource families such as
`ctl assets`, `ctl asset-channels`, `ctl plans`, `ctl tenant-accounts`, and many
more. These target the **Control Plane API** through named contexts rather than
a raw gateway URL + API key:

- Connection is resolved from a named context (`ferrogate context create ...`)
  or the `--endpoint` / `--tenant` / `--token-env` overrides, following a
  deterministic `flag > env > context > default` precedence.
- Tokens are never stored in a context — only *how to obtain* them
  (`--token-env` / `--token-stdin`).

Choose per task:

- Talking directly to a running **gateway** with a virtual API key → keep using
  `ferrogate assets` / `ferrogate plans`.
- Talking to the **Control Plane API** with a managed context/credential → use
  the `ferrogate ctl ...` families.

Both surfaces coexist; the `ctl` namespace was chosen precisely so its nouns
never collide with the top-level `assets` / `plans` commands.

## 3. Shell completions and the command reference (issue #365)

New in this slice:

- `ferrogate completions <shell>` prints a completion script for bash, zsh,
  fish, powershell, or elvish, generated from the full command tree (including
  every `ctl` resource family). Example:

  ```sh
  ferrogate completions bash > /etc/bash_completion.d/ferrogate
  ferrogate completions zsh  > "${fpath[1]}/_ferrogate"
  ```

- [`docs/cli-reference.md`](cli-reference.md) is a generated, drift-checked
  reference of the complete command tree. Regenerate it after any command-surface
  change with:

  ```sh
  FERROGATE_REGENERATE_DOCS=1 cargo test -p ferrogate-cli reference
  ```

  Because it is derived from the command tree, it covers flags and their `[env:
  ...]` bindings only. Two client-attribution variables are **not** flags and so
  are documented by hand instead:
  [`docs/cli-audit-attribution.md`](cli-audit-attribution.md) describes
  `FERROGATE_CLIENT_HOST_LABEL` and `FERROGATE_CLIENT_REPORTED_IP`, what every
  request now carries about the client (issue #548), and how the mandatory
  server-time challenge and deployment keyring make `client_sent_at`
  authoritative before an API operation is sent.
