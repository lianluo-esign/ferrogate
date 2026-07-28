# CLI audit attribution: `action_id`, the client fingerprint, and the two instants

Issue #548. Every request the `ferrogate` CLI issues — **reads included** —
carries an identifier for the operator action that produced it, a description of
the client that produced it, and the client's own clock reading. This page is
the operator-facing half: what is sent, what is optional, what a receipt says,
and which fields the server treats as authoritative.

The design decisions and their rejected alternatives live in the code, in
`crates/ferrogate-control-plane-client/src/action_identity.rs`. This page does
not repeat them; it documents behaviour you can observe and configuration you
can set.

## What is sent, on every request

| header | authority | always? |
|---|---|---|
| `x-ferrogate-action-id` | client-minted identifier | yes |
| `x-ferrogate-client-fingerprint` | client-asserted | yes |
| `x-ferrogate-client-clock-unverified` | client-asserted, **untrusted** | yes |
| `x-ferrogate-time-token` | **server**-issued, echoed verbatim | only after an earlier response in the same action supplied one |
| `x-ferrogate-client-reported-ip` | client-asserted, **opt-in** | only when you set the variable below |

`action_id` is `fgact_` followed by 32 lowercase hex characters, minted once per
invocation from the OS CSPRNG. Every request of that invocation carries the same
value: every page of an `--all-pages` walk, and every retry of the same logical
action. It is **not** an idempotency key — an idempotency key answers "may this
effect be applied again?", and the two are carried separately and rendered
separately on a receipt.

The fingerprint is a `v1;`-prefixed, `;`-delimited list of `cli`, `os`, `arch`,
`context`, `cred` and (when disclosed) `host`. Values are percent-encoded, so
the header is always printable ASCII and an operator-supplied value can never
introduce a delimiter or split the request. **`cred` names the credential
_source_** — `env:FERROGATE_TOKEN`, `stdin`, `inline` or `none` — and never the
credential itself; no token, and no digest of a token, is ever sent.

Percent-encoding is reversible, not a digest: a value like `生产` arrives as
`%E7%94%9F%E4%BA%A7` and decodes back to what you wrote. A literal `%` in your
own label is escaped to `%25`, so one decode pass always returns your text and
never a delimiter.

### If something between you and the control plane strips headers

These are ordinary request headers with no fallback. A corporate proxy, an API
gateway or a service mesh configured to forward only a header allow-list will
drop `x-ferrogate-*` **silently** — the request still succeeds, and the action
is simply recorded without attribution. There is no error, no warning and
nothing on the receipt to distinguish it from a CLI that never sent them.

If your audit trail shows actions with no `action_id`, the intermediary is the
first place to look: add `x-ferrogate-action-id`,
`x-ferrogate-client-fingerprint` and `x-ferrogate-client-clock-unverified` to
its forward list (plus `x-ferrogate-client-reported-ip` if you opted in).

## The two opt-in variables

Neither is a command-line flag, so neither appears in the generated
[`cli-reference.md`](cli-reference.md). Both are **off by default**.

### `FERROGATE_CLIENT_HOST_LABEL`

A machine label of your choosing, added to the fingerprint as `host=<label>`.

```sh
export FERROGATE_CLIENT_HOST_LABEL=ci-runner-7
```

The CLI **does not detect your hostname**, and will not. A hostname is the
highest-PII field a client could collect; it is collected without the operator
ever deciding to disclose it; and in a multi-tenant control plane it names your
internal estate to whoever reads the audit stream. This variable replaces it:
you choose the value, it may be a pseudonym or a CI job id, and unset means the
field is omitted entirely rather than sent blank.

### `FERROGATE_CLIENT_REPORTED_IP`

An address you choose to disclose about the client, sent on its own header
`x-ferrogate-client-reported-ip`.

```sh
export FERROGATE_CLIENT_REPORTED_IP=203.0.113.9
```

It rides **outside** the fingerprint blob on purpose. The client is not the
authority on its own address: it cannot reliably know its public one, and
anything it says is self-asserted and trivially forged. The authoritative answer
to "where did this action come from" is the source IP the **server** observes,
which no client can suppress and which is not in this record at all. The header
name says `client-reported` so the two can never be merged.

### Neither variable can blind an audit trail

Because both start off, no part of the correlation guarantee rests on them:
`action_id` is always present, and the server's own observations are unaffected.
Opting in adds evidence; opting out removes none the server did not already
hold.

## The timestamp: server authority before the effect

The audit instant is **server-issued or the API request is not sent**. The CLI
never fills it from its own clock, and there is no code path from the local
clock into that field.

Before the first API request of a logical action, the CLI sends one safe
`GET /healthz` challenge with the same `x-ferrogate-action-id` and fingerprint.
FerroGate returns a short-lived, HMAC-signed `x-ferrogate-time-token`; the CLI
accepts it and presents it on the actual API request. If the challenge fails or
does not return an acceptable token, the API request is refused locally. The
challenge has no control-plane effect and is the only attributed request allowed
to omit the token. The standalone Control Plane listener answers ordinary
liveness locally but forwards attributed health challenges to the gateway, so
both listener topologies use the same deployment keyring and validation path.

The server validates the echoed token's HMAC signature, action-id binding and
TTL against its own receive clock. An expired token, a bad signature, a token
moved to another action, or an effect request with no token is rejected before
the handler runs. Successful responses can refresh the held token for retries
or later pages of the same action.

Beside it, `client_clock_unverified_unix` is always present. It is the client's
own reading, and it is **evidence about the client, never the event time**: no
authorization or ordering decision may read it. The two exist separately because
one field cannot express clock skew — a host running hours behind, a suspended
VM, a backdated workstation — and the difference between them is the finding an
auditor needs.

The cost is explicit: one bounded challenge round trip per logical action. A
single-request verb makes one challenge plus one timestamped API request; an
N-page walk makes one challenge plus N timestamped API requests. No token is
cached between CLI invocations.

> **Known client-side limitation.** The client also refuses a token
> that falls outside its declared TTL by more than five minutes, judged against
> the client's own clock — the one this whole design calls untrusted. The
> reading is taken once, when the command starts, so a machine whose clock is
> further out than five minutes, or an invocation that runs longer than that,
> will refuse the challenge token and will not send the API request. The refusal
> is printed on stderr. That is precisely the skewed-host case this page says
> the two instants exist to expose, so it is a real availability gap and not a
> theoretical one; removing the client-side window check in favour of the
> server's own TTL is deferred work.

### Deployment authority and rotation

Attributed CLI traffic requires an explicit deployment keyring:

* `FERROGATE_CLIENT_ACTION_TIME_SIGNING_KEY` is the active standard-base64
  encoding of exactly 32 random bytes. Every replica must use the same active
  key. Without it, ordinary non-attributed traffic remains available, but any
  request carrying an action id fails closed and the CLI will not send its API
  operation.
* `FERROGATE_CLIENT_ACTION_TIME_TRUSTED_KEYS` is an optional comma-separated
  list of standard-base64 32-byte verification keys used during rotation.
* `FERROGATE_CLIENT_ACTION_TIME_TTL_SECONDS` is optional, defaults to 30, and
  must be between 1 and 60.

Rotate in two phases so load balancing never sends a token to a replica that
cannot verify it: first deploy the new key in every replica's trusted list while
the old key remains active; then make the new key active everywhere while the
old key stays trusted. Remove the old key only after the maximum token TTL has
elapsed. The keyring is read at process startup, so rotation is a rolling
deployment, not a hot config reload.

`ferrogate ctl <group> <verb> --output json` renders all of this under
`client_identity`; `--output table` renders it as `client.*` rows, each labelled
with its authority.

## Coverage, and its edge

Two originating code paths put bytes on the wire. Both require an action
identity while building the request, and both production adapters have a
loopback test over the bytes received from a socket:

* `ferrogate ctl ...` and `ferrogate ops ...` go through the typed client's
  `prepare_request`, which takes a `&ClientActionIdentity` and is the only
  function that materializes a request. A new verb cannot omit the attribution
  while building the request, because it cannot obtain a `PreparedRequest`
  without one. `reqwest_transport_writes_the_identity_onto_the_socket` separately
  proves that the production adapter copies those prepared headers onto the
  wire; the compile-time argument alone does not prove adapter behavior.
* `ferrogate assets ...` and `ferrogate plans ...` predate the typed client and
  drive a hand-rolled raw-TCP HTTP client; its `send_request` takes the same
  required argument, for the same reason. Between them that is seven requests —
  four mutations, two of which (`plans create`, `plans assign`) are Control
  Plane mutations with no `ctl` family to route through instead.

`ferrogate admin-api` is deliberately **not** on this list: it is a reverse
proxy relaying a request the admin console made, and minting an `action_id`
there would attribute the console's action to the proxy process. The proxy does
relay the caller's own `x-ferrogate-*` headers untouched — they are not
hop-by-hop and the forward loop passes them through — **but the admin console
does not send any today**. So a mutation an operator makes in the console is
recorded without an `action_id`, exactly as it was before this issue. Attributing
console actions means minting an identity in the console and is separate work;
it is not covered by anything on this page.

One HTTP path sits outside those two client implementations but carries the
same identity:

* `ferrogate reload --admin-url …` mutates a running gateway's live config
  through a third raw-TCP client in the `ferrogate-gateway` crate. The command
  mints one identity and threads every rendered header through
  `execute_admin_reload` to that socket write. A bounded loopback test asserts
  the actual request head.

`ferrogate storage migrate-to-supabase` talks to PostgreSQL, not HTTP, so an
HTTP attribution header does not apply there.

Inside `ferrogate-cli` the known set is checked: a test
(`every_outbound_http_call_goes_through_an_attributed_chokepoint`) holds an
allow-list of every raw socket **and every `reqwest` client** that crate
constructs directly, including `reqwest` imports and common `TcpStream` aliases,
so a fourth hand-rolled client there fails the suite. This is a lexical
tripwire, not Rust name resolution: a client re-exported by another already
linked crate can evade it. The two loopback tests are the behavioral evidence
for the actual production chokepoints; the source census makes a new direct
bypass conspicuous rather than pretending to prove all future Rust names.

## Where this is held by a test, and where it is only written down

| claim | held by |
|---|---|
| every registered `ctl`/`ops` request prepares the identity | `every_registered_verb_prepares_the_action_identity_for_transport` plus the closed, getter-only `PreparedRequest` API |
| the production `ctl`/`ops` adapter writes the prepared identity onto the socket | `reqwest_transport_writes_the_identity_onto_the_socket`, against a loopback listener |
| the raw-TCP client writes the identity onto the socket | `send_request_writes_the_identity_onto_the_socket`, against a loopback listener |
| no fourth HTTP client appears in `ferrogate-cli` | `every_outbound_http_call_goes_through_an_attributed_chokepoint` |
| no local clock reaches the audit instant | two source guards, one per crate |
| the fingerprint field set | `the_fingerprint_declares_exactly_the_reviewed_field_set` |
| every API response declares the server time token | `every_response_declares_the_server_time_token`, over the contract |
| `ferrogate reload` carries one identity | `admin_reload_mints_and_threads_one_action_identity` plus `admin_reload_writes_every_client_action_identity_header_to_the_socket` |
| the admin console | **nothing** — stated above, not tested |

## Privacy summary

* Nothing is hashed, because nothing collected needs to be.
* No credential material is sent, in any form, including digests and prefixes.
* The hostname, username, working directory and argv are **not** collected.
* The two PII-bearing fields are opt-in and off.
* The exact field set is pinned by a test, so adding a field is a review event
  rather than a refactor.
