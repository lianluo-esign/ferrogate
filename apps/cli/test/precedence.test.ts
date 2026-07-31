import { describe, expect, test } from "vitest";
import { parseArgs } from "../src/args.js";
import type { Context, ContextStore } from "../src/context.js";
import {
  DEFAULT_ENDPOINT,
  DEFAULT_TIMEOUT_MILLIS,
  envOverrides,
  resolve,
  unhonoredScopeNotice,
} from "../src/context.js";
import { CliError } from "../src/errors.js";
import { GLOBAL_FLAGS, globalOverrides } from "../src/global-args.js";

const CONTEXT: Context = {
  name: "prod",
  endpoint: "https://ctx.example",
  tenant: "tenant-from-context",
  project: "proj-1",
  workspace: "ws-1",
  tlsInsecureSkipVerify: false,
  auth: { kind: "env", var: "PROD_TOKEN" },
};

const STORE: ContextStore = { contexts: [CONTEXT], current: "prod" };

function overridesFrom(argv: readonly string[]) {
  return globalOverrides(parseArgs(argv, GLOBAL_FLAGS));
}

describe("precedence: flag > env > context > default", () => {
  test("flag beats env, context, and default", () => {
    const effective = resolve(
      STORE,
      envOverrides({ FERROGATE_ENDPOINT: "https://env.example" }),
      overridesFrom(["--endpoint", "https://flag.example"]),
    );
    expect(effective.endpoint).toBe("https://flag.example");
  });

  test("env beats context and default", () => {
    const effective = resolve(
      STORE,
      envOverrides({ FERROGATE_ENDPOINT: "https://env.example" }),
      overridesFrom([]),
    );
    expect(effective.endpoint).toBe("https://env.example");
  });

  test("context beats default", () => {
    const effective = resolve(STORE, envOverrides({}), overridesFrom([]));
    expect(effective.endpoint).toBe("https://ctx.example");
  });

  test("default applies when no layer supplies a value", () => {
    const effective = resolve({ contexts: [] }, envOverrides({}), overridesFrom([]));
    expect(effective.endpoint).toBe(DEFAULT_ENDPOINT);
    expect(effective.timeoutMillis).toBe(DEFAULT_TIMEOUT_MILLIS);
    expect(effective.auth).toEqual({ kind: "none" });
  });

  test("the same chain governs tenant", () => {
    expect(
      resolve(
        STORE,
        envOverrides({ FERROGATE_TENANT: "env-t" }),
        overridesFrom(["--tenant", "flag-t"]),
      ).tenant,
    ).toBe("flag-t");
    expect(
      resolve(STORE, envOverrides({ FERROGATE_TENANT: "env-t" }), overridesFrom([])).tenant,
    ).toBe("env-t");
    expect(resolve(STORE, envOverrides({}), overridesFrom([])).tenant).toBe("tenant-from-context");
  });

  test("the same chain governs which context is selected", () => {
    const store: ContextStore = {
      contexts: [CONTEXT, { ...CONTEXT, name: "staging", endpoint: "https://staging.example" }],
      current: "prod",
    };
    expect(resolve(store, envOverrides({}), overridesFrom(["--context", "staging"])).endpoint).toBe(
      "https://staging.example",
    );
    expect(
      resolve(store, envOverrides({ FERROGATE_CONTEXT: "staging" }), overridesFrom([])).endpoint,
    ).toBe("https://staging.example");
    expect(resolve(store, envOverrides({}), overridesFrom([])).endpoint).toBe(
      "https://ctx.example",
    );
  });

  test("an env-selected context does not outrank a flag-selected one", () => {
    const store: ContextStore = {
      contexts: [CONTEXT, { ...CONTEXT, name: "staging", endpoint: "https://staging.example" }],
    };
    const effective = resolve(
      store,
      envOverrides({ FERROGATE_CONTEXT: "staging" }),
      overridesFrom(["--context", "prod"]),
    );
    expect(effective.contextName).toBe("prod");
  });

  test("credential source follows the chain and never carries a token value", () => {
    expect(resolve(STORE, envOverrides({}), overridesFrom([])).auth).toEqual({
      kind: "env",
      var: "PROD_TOKEN",
    });
    expect(resolve(STORE, envOverrides({}), overridesFrom(["--token-env", "OTHER"])).auth).toEqual({
      kind: "env",
      var: "OTHER",
    });
    expect(resolve(STORE, envOverrides({}), overridesFrom(["--token-stdin"])).auth).toEqual({
      kind: "stdin",
    });
  });

  test("project/workspace come only from the context — no flag or env layer exists", () => {
    const effective = resolve(STORE, envOverrides({}), overridesFrom([]));
    expect(effective.project).toBe("proj-1");
    expect(effective.workspace).toBe("ws-1");
  });
});

describe("refusals in the precedence layer", () => {
  test("a named-but-undefined context refuses instead of falling back", () => {
    expect(() =>
      resolve(STORE, envOverrides({}), overridesFrom(["--context", "ghost"])),
    ).toThrowError(/selected context 'ghost' is not defined/);
  });

  test("a non-numeric FERROGATE_TIMEOUT_MILLIS refuses instead of being ignored", () => {
    expect(() => envOverrides({ FERROGATE_TIMEOUT_MILLIS: "soon" })).toThrowError(CliError);
  });

  test("an unknown --output format refuses", () => {
    expect(() => overridesFrom(["--output", "yaml"])).toThrowError(/unknown output format/);
  });
});

describe("honesty: unhonored scope note", () => {
  test("a tenant produces the header-only note", () => {
    const notice = unhonoredScopeNotice(resolve(STORE, envOverrides({}), overridesFrom([])));
    expect(notice).toContain("x-ferrogate-tenant");
    expect(notice).toContain("--filter tenant=<id>");
  });

  test("project and workspace are reported as recorded-but-not-sent", () => {
    const notice = unhonoredScopeNotice(resolve(STORE, envOverrides({}), overridesFrom([])));
    expect(notice).toContain("project and workspace are recorded locally and are not sent");
  });

  test("a bare context produces no note at all", () => {
    const store: ContextStore = {
      contexts: [
        {
          name: "bare",
          endpoint: "https://x",
          tlsInsecureSkipVerify: false,
          auth: { kind: "none" },
        },
      ],
      current: "bare",
    };
    expect(
      unhonoredScopeNotice(resolve(store, envOverrides({}), overridesFrom([]))),
    ).toBeUndefined();
  });
});
