# CLI audit attribution: `action_id`, the client fingerprint, and the two instants

Issue #548. Every request the `ferrogate` CLI issues — **reads included** —
carries an identifier for the operator action that produced it, a description of
the client that produced it, and the client's own clock reading. This page is
the operator-facing half: what is sent, what is optional, what a receipt says,
and what is **not honored by the server today**.

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
| `x-ferrogate-time-token` | **server**-issued, echoed verbatim | only when one is held (see below — never, today) |
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

## The timestamp: what a receipt says, and why it says `null`

The audit instant is **server-issued or absent**. The CLI never fills it from
its own clock, and there is no code path from the local clock into that field.

> **NOT ISSUED BY ANY FERROGATE DEPLOYMENT TODAY.** The endpoint that mints a
> time token is server-side work issue #548 defers, and the contract declares
> `x-ferrogate-time-token` on zero responses. So on **every** receipt this CLI
> renders today, `client_sent_at` is `null` with the absence code
> `no_server_issued_time_token`.

That is a stated absence, not a silence, and it is the deliberate outcome: an
instant read from a skewed or hostile client clock is a *false* record in a
security-audit trail, which is worse than an absent one. The server's own
receive time still bounds the action from the other side.

Beside it, `client_clock_unverified_unix` is always present. It is the client's
own reading, and it is **evidence about the client, never the event time**: no
authorization or ordering decision may read it. The two exist separately because
one field cannot express clock skew — a host running hours behind, a suspended
VM, a backdated workstation — and the difference between them is the finding an
auditor needs.

When a server does start issuing tokens, the client will harvest one off any
response that carries the header and present it on the **next** request of the
same action (a "piggy-back": no preflight request is ever made, so the extra
round-trip cost is zero). A token bound to a different action is refused
unconditionally. Note that a mutating verb is always the first request of its
action, so a receipt's `client_sent_at` will stay `null` until something makes a
mutation the second request of an action; the saving lands on multi-request
reads, which produce no receipt.

> **Known limitation, when that day comes.** The client also refuses a token
> that falls outside its declared TTL by more than five minutes, judged against
> the client's own clock — the one this whole design calls untrusted. The
> reading is taken once, when the command starts, so a machine whose clock is
> further out than five minutes, or an invocation that runs longer than that,
> will refuse **every** token and report `client_sent_at: null` with the same
> absence code as "none was issued". The refusal is printed on stderr and is not
> distinguished on the receipt. That is precisely the skewed-host case this page
> says the two instants exist to expose, so it is a real gap and not a
> theoretical one; removing the client-side window check in favour of the
> server's own TTL is deferred work.

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

Two originating requests from the CLI itself are still **outside** both
chokepoints, and are named here rather than left to be discovered:

* `ferrogate reload --admin-url …` mutates a running gateway's live config
  through a third raw-TCP client that lives in the `ferrogate-gateway` crate. It
  carries no `action_id` today; closing it is follow-up work.
* `ferrogate storage migrate-to-supabase` talks to PostgreSQL, not HTTP, and
  carries no header at all.

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
| nothing issues a time token yet | `no_operation_yet_issues_a_server_time_token`, over the contract |
| `ferrogate reload` and the admin console | **nothing** — stated above, not tested |

## Privacy summary

* Nothing is hashed, because nothing collected needs to be.
* No credential material is sent, in any form, including digests and prefixes.
* The hostname, username, working directory and argv are **not** collected.
* The two PII-bearing fields are opt-in and off.
* The exact field set is pinned by a test, so adding a field is a review event
  rather than a refactor.
