# CLI Catalog Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement issue #816's provider/model/offering Admin API commands and idempotent env import in the existing Bun CLI.

**Architecture:** Add one catalog command module under `apps/cli/src/commands` that owns field-flag mapping, model-show composition, import mapping, and catalog-specific rendering. It will use the existing `resolveEffective`, `ClientActionIdentity`, `requestContextFor`, and `ControlPlaneClient` seams. Add registry descriptors only for the missing OpenAPI operation ids so the existing parity gate remains authoritative; no CLI code will import D1 or gateway storage.

**Tech Stack:** Bun, TypeScript, Vitest, existing `CommandNode` parser, `ControlPlaneClient`, `renderTable`/`renderJson`, Admin API contract in `docs/openapi/runtime-api-contract.json`.

---

### Task 1: Pin the command contract with failing CLI tests

**Files:**
- Create: `apps/cli/test/catalog.test.ts`
- Modify: `apps/cli/test/help.test.ts`

- [ ] **Step 1: Write the failing tests**

Add tests that drive `main()` with `createTestRuntime()` and assert the real
in-memory client requests. Cover:

```ts
test("provider add sends an Admin API body and renders a table", async () => {
  const runtime = createTestRuntime({
    script: { "POST /admin/v1/providers": ok({ object: "provider", provider: { id: "openai" } }) },
  });
  expect(await main(["provider", "add", "--name", "openai", "--kind", "openai", "--base-url", "https://api.openai.com/v1", "--api-key-var", "OPENAI_API_KEY"], runtime)).toBe(0);
  expect(runtime.client.requests[0]?.spec.body).toEqual({
    id: "openai", name: "openai", kind: "openai", base_url: "https://api.openai.com/v1", api_key_var: "OPENAI_API_KEY",
  });
  expect(runtime.stdout()).toContain("PROVIDER");
});

test("a live-looking api-key-var is rejected before any request", async () => {
  const runtime = createTestRuntime();
  expect(await main(["provider", "add", "--name", "x", "--kind", "openai", "--base-url", "https://x.test", "--api-key-var", "sk-live-example-key"], runtime)).toBe(2);
  expect(runtime.client.requests).toHaveLength(0);
  expect(`${runtime.stdout()}${runtime.stderr()}`).not.toContain("sk-live-example-key");
});

test("model show combines the model and all offerings in the money table", async () => {
  const runtime = createTestRuntime({
    script: {
      "GET /admin/v1/models/fast": ok({ model: { id: "fast", name: "fast" } }),
      "GET /admin/v1/models/fast/offerings": ok({ data: [{ id: "o1", provider: "openai", input_price_per_1m: 0.25, output_price_per_1m: 1.5 }] }),
    },
  });
  expect(await main(["model", "show", "fast"], runtime)).toBe(0);
  expect(runtime.stdout()).toContain("0.25");
  expect(runtime.stdout()).toContain("1.5");
});

test("json output round-trips the combined model document", async () => {
  const runtime = createTestRuntime({
    script: {
      "GET /admin/v1/models/fast": ok({ model: { id: "fast", name: "fast" } }),
      "GET /admin/v1/models/fast/offerings": ok({ data: [{ id: "o1", input_price_per_1m: 0.25 }] }),
    },
  });
  await main(["model", "show", "fast", "--json"], runtime);
  expect(JSON.parse(runtime.stdout())).toEqual({ id: "fast", name: "fast", offerings: [{ id: "o1", input_price_per_1m: 0.25 }] });
});

test("a server 409 keeps its message and exits non-zero", async () => {
  const runtime = createTestRuntime({
    script: { "DELETE /admin/v1/providers/openai": { status: 409, body: { error: { code: "catalog_conflict", message: "provider openai has live offerings" } } } },
  });
  expect(await main(["provider", "rm", "openai"], runtime)).toBe(4);
  expect(runtime.stderr()).toContain("provider openai has live offerings");
});
```

Also assert the new native command paths appear in help. Keep fixture data
small; add a four-offering model fixture for the acceptance-shaped money-view
test and change one price in a second assertion so the renderer cannot pass
without using input data.

- [ ] **Step 2: Run the focused tests to verify RED**

Run: `bun run --filter '@ferrogate/cli' test -- test/catalog.test.ts test/help.test.ts`

Expected: FAIL because `provider`/`model` are not present in the command tree.

- [ ] **Step 3: Commit the test-only red state locally after confirming the failure**

Do not create the PR from this commit; retain the red evidence in the working
history only if it helps the review trail, then implement immediately.

### Task 2: Add parity descriptors for all catalog CRUD operations

**Files:**
- Modify: `apps/cli/src/registry.ts`
- Test: `apps/cli/test/parity.test.ts`

- [ ] **Step 1: Add registry groups and request builders**

Keep `catalog models` and `catalog providers` list verbs unchanged. Add:

```ts
{
  name: "providers",
  about: "Manage provider channels",
  verbs: [
    read("show", "Show a provider channel", "getAdminProvider"),
    mutating("add", "Create a provider channel", "createAdminProvider"),
    mutating("replace", "Replace a provider channel", "replaceAdminProvider"),
    mutating("update", "Patch a provider channel", "patchAdminProvider"),
    mutating("rm", "Delete a provider channel", "deleteAdminProvider"),
  ],
  build: (verb, input) => buildAliasedCrud(PROVIDERS, verb, input, "provider"),
},
{
  name: "models",
  about: "Manage logical models",
  verbs: [
    read("show", "Show a logical model", "getAdminModel"),
    mutating("add", "Create a logical model", "createAdminModel"),
    mutating("replace", "Replace a logical model", "replaceAdminModel"),
    mutating("update", "Patch a logical model", "patchAdminModel"),
    mutating("rm", "Delete a logical model", "deleteAdminModel"),
  ],
  build: (verb, input) => buildAliasedCrud(MODELS, verb, input, "model"),
},
{
  name: "model-offerings",
  about: "Manage model offerings",
  verbs: [
    read("list", "List offerings for a model", "listAdminModelOfferings"),
    read("show", "Show a model offering", "getAdminModelOffering"),
    mutating("add", "Attach a model offering", "createAdminModelOffering"),
    mutating("replace", "Replace a model offering", "replaceAdminModelOffering"),
    mutating("update", "Patch a model offering", "patchAdminModelOffering"),
    mutating("rm", "Delete a model offering", "deleteAdminModelOffering"),
  ],
  build: (verb, input) => buildOfferingRequest(verb, input),
},
```

The helper must map `show/add/rm` to the existing `ResourceApi.get/create/delete`
methods and require one model segment plus one offering segment for nested item
verbs. It must not add duplicate list descriptors for provider/model.

- [ ] **Step 2: Run parity and focused registry tests**

Run: `bun run --filter '@ferrogate/cli' test -- test/parity.test.ts`

Expected: PASS for the 16 previously missing operation ids.

### Task 3: Implement provider/model/offering commands with TDD

**Files:**
- Create: `apps/cli/src/commands/catalog.ts`
- Modify: `apps/cli/src/tree.ts`
- Test: `apps/cli/test/catalog.test.ts`

- [ ] **Step 1: Add the minimal shared command helpers**

Implement `JSON_FLAG`, common catalog flags, `requestSession`, request-id/
trace-id stderr reporting, `emitCatalogBody`, `asList`, and `asItem`. Reuse
`resolveEffective`, `ClientActionIdentity.mint`, `fingerprintEnvFrom`, and the
exported `requestContextFor`; call only `runtime.client.send`.

- [ ] **Step 2: Add provider and model CRUD leaves**

Use field flags to build bodies. `add` requires the issue's required identity
fields and sends `id=name`; update sends only flags explicitly present. Numeric
and boolean parsing uses `Args`; capability parsing only splits comma-separated
syntax and leaves capability validity to the server. `show` and `rm` address the
name/id assumption recorded in the design.

- [ ] **Step 3: Add nested offering leaves**

Implement `add`, `list` with alias `ls`, `show`, `update`, and `rm`. Direct
two-argument item calls use the nested route. One-argument item calls resolve
the model id by Admin API list reads, matching by offering id; no request body or
local catalog validation is invented.

- [ ] **Step 4: Add the model money view**

Fetch the model and offerings, merge to `{ ...model, offerings }` for JSON, and
render a model metadata table plus an offering table whose price cells are
derived from each offering. The renderer must show `-` for null/undefined and
must use the actual numeric values.

- [ ] **Step 5: Add the credential-shape guard**

Reject `sk-*`-shaped `--api-key-var` values before `requestSession` and without
including the raw value in the error. Apply the same guard to imported provider
rows before any import list request.

- [ ] **Step 6: Add env import and idempotence**

Parse `GATEWAY_PROVIDERS`/`GATEWAY_MODELS` JSON arrays, map provider/model
records and primary/fallback/canary/shadow routes to Admin API bodies, list
existing rows, and POST only missing rows. Match existing rows by stable id or
logical identity and use deterministic ids for newly imported offerings. Emit a
summary table or JSON document with created/existing counts.

- [ ] **Step 7: Wire the command tree**

Add `providerCommand` and `modelCommand` to `COMMANDS`, with all leaf handlers
owning their flag lists. Ensure group nodes have no accidental run handler and
all help paths render.

- [ ] **Step 8: Run the focused CLI suite**

Run: `bun run --filter '@ferrogate/cli' test -- test/catalog.test.ts test/help.test.ts test/parity.test.ts`

Expected: PASS, including the four-offering price mutation assertion and zero
requests on credential rejection.

### Task 4: Add API-backed import and control-plane end-to-end coverage

**Files:**
- Modify: `apps/cli/test/catalog.test.ts`
- Modify: `apps/control-plane/test/admin-model-catalog.test.ts` only if a missing
  CLI-facing contract assertion is needed; otherwise leave it unchanged.

- [ ] **Step 1: Add a stateful fake-client import test**

Run `provider import --from-env` twice against a fake client that updates its
in-memory provider/model/offering lists after POST. Assert exactly one create
per desired row and that the second run emits zero creates.

- [ ] **Step 2: Add the four-offering Admin API acceptance chain**

Keep the existing control-plane harness as the authoritative D1-backed proof:
create a channel, model, and four priced roles, then read the nested list and
assert all four prices. The CLI test drives the same request paths and proves
the money renderer and JSON round-trip; do not add direct D1 access to CLI.

- [ ] **Step 3: Run the two focused packages**

Run: `bun run --filter '@ferrogate/cli' test` and
`bun run --filter '@ferrogate/app-control-plane' test`.

Expected: CLI tests pass with parity clean; control-plane tests retain their
existing full pass count.

### Task 5: Reviewable commit and PR, then full verification

**Files:**
- All implementation/test files above plus the two committed design documents.

- [ ] **Step 1: Inspect diff and secret hygiene**

Run `git diff --check`, `git status --short`, and searches for literal
credential values or direct D1 imports under `apps/cli`. Confirm only
`/home/dev/wt/pr816` is dirty.

- [ ] **Step 2: Commit the first reviewable implementation**

Use a focused commit message such as
`feat(cli): manage provider model catalog via admin api`.

- [ ] **Step 3: Push and create the PR early**

Run:

```bash
git push -u origin feat/issue-816-cli-catalog
gh pr create --title "feat(cli): manage provider model catalog" --body "Closes #816\n\nImplements provider/model/offering Admin API commands, secure binding-name handling, and idempotent env import."
```

Do not merge, delete the branch, or remove the worktree. Continue subsequent
fixes and commits on this same PR.

- [ ] **Step 4: Run issue verification commands**

Run each command fresh and record its exit status:

```bash
bun run --filter '@ferrogate/cli' test
bun run --filter '@ferrogate/cli' typecheck
bun run --filter '@ferrogate/app-control-plane' test
bun run typecheck
bun run lint
```

Also run `git diff --check` and the relevant mutation checks. Report any
failures that reproduce baseline and distinguish them from regressions.

