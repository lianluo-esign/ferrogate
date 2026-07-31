import { describe, expect, test } from "vitest";
import { type FlagSpec, parseArgs } from "../src/args.js";
import { CliError } from "../src/errors.js";

const SPECS: readonly FlagSpec[] = [
  {
    name: "config",
    short: "c",
    kind: "string",
    valueName: "PATH",
    env: "FERROGATE_CONFIG",
    default: "Ferrogate/Caddyfile",
    help: "config",
  },
  { name: "upgrade", kind: "boolean", help: "upgrade" },
  { name: "verbose", short: "v", kind: "boolean", help: "verbose" },
  { name: "quiet", short: "q", kind: "boolean", help: "quiet" },
  { name: "limit", kind: "number", valueName: "N", help: "limit" },
  { name: "filter", kind: "string", valueName: "KEY=VALUE", repeatable: true, help: "filter" },
  {
    name: "sort",
    kind: "string",
    valueName: "FIELD",
    repeatable: true,
    allowHyphenValues: true,
    help: "sort",
  },
  { name: "data", kind: "string", valueName: "JSON", help: "data", conflictsWith: ["file"] },
  { name: "file", kind: "string", valueName: "PATH", help: "file", conflictsWith: ["data"] },
];

describe("parseArgs — long and short forms", () => {
  const cases: readonly (readonly [string, readonly string[], string])[] = [
    ["--flag value", ["--config", "a.conf"], "a.conf"],
    ["--flag=value", ["--config=b.conf"], "b.conf"],
    ["-c value", ["-c", "c.conf"], "c.conf"],
    ["-c=value", ["-c=d.conf"], "d.conf"],
    ["-cVALUE", ["-ce.conf"], "e.conf"],
  ];
  for (const [label, argv, expected] of cases) {
    test(label, () => {
      expect(parseArgs(argv, SPECS).getString("config")).toBe(expected);
    });
  }
});

describe("parseArgs — positionals, booleans, passthrough", () => {
  test("positionals keep their order and are not flags", () => {
    const args = parseArgs(["alpha", "beta", "--upgrade", "gamma"], SPECS);
    expect(args.positionals).toEqual(["alpha", "beta", "gamma"]);
    expect(args.getBoolean("upgrade")).toBe(true);
  });

  test("bundled boolean shorts each set their flag", () => {
    const args = parseArgs(["-vq"], SPECS);
    expect(args.getBoolean("verbose")).toBe(true);
    expect(args.getBoolean("quiet")).toBe(true);
  });

  test("everything after `--` is passthrough and never parsed", () => {
    const args = parseArgs(["--upgrade", "--", "--not-a-flag", "-x"], SPECS);
    expect(args.getBoolean("upgrade")).toBe(true);
    expect(args.passthrough).toEqual(["--not-a-flag", "-x"]);
    expect(args.positionals).toEqual([]);
  });

  test("--help and --version are detected ahead of validation", () => {
    const args = parseArgs(["--help"], SPECS);
    expect(args.help).toBe(true);
    expect(parseArgs(["--version"], SPECS).version).toBe(true);
  });
});

describe("parseArgs — repeatable flags", () => {
  test("--filter collects every occurrence in order", () => {
    const args = parseArgs(["--filter", "a=1", "--filter", "b=2"], SPECS);
    expect(args.getAll("filter")).toEqual(["a=1", "b=2"]);
  });

  test("a non-repeatable flag keeps the last value", () => {
    expect(parseArgs(["--config", "one", "--config", "two"], SPECS).getString("config")).toBe(
      "two",
    );
  });

  test("--sort accepts a leading hyphen (descending key)", () => {
    expect(parseArgs(["--sort", "-created_at"], SPECS).getAll("sort")).toEqual(["-created_at"]);
  });
});

describe("parseArgs — refusals", () => {
  test("an unknown long flag is a usage error, not a silent drop", () => {
    expect(() => parseArgs(["--nope"], SPECS)).toThrowError(CliError);
    try {
      parseArgs(["--nope"], SPECS);
    } catch (error) {
      expect((error as CliError).exitCode()).toBe(2);
    }
  });

  test("an unknown short flag is a usage error", () => {
    expect(() => parseArgs(["-z"], SPECS)).toThrowError(/unknown flag '-z'/);
  });

  test("a value-taking flag with no value refuses", () => {
    expect(() => parseArgs(["--config"], SPECS)).toThrowError(/--config expects a PATH value/);
  });

  test("conflicting flags refuse", () => {
    expect(() => parseArgs(["--data", "{}", "--file", "x.json"], SPECS)).toThrowError(
      /--data cannot be used with --file/,
    );
  });

  test("a non-numeric number refuses rather than coercing to NaN", () => {
    expect(() => parseArgs(["--limit", "many"], SPECS).getNumber("limit")).toThrowError(
      /--limit expected a number/,
    );
  });
});

describe("parseArgs — flag > env > default", () => {
  const env = { FERROGATE_CONFIG: "from-env.conf" };

  test("flag beats env", () => {
    expect(parseArgs(["--config", "from-flag.conf"], SPECS, { env }).getString("config")).toBe(
      "from-flag.conf",
    );
  });

  test("env beats default", () => {
    expect(parseArgs([], SPECS, { env }).getString("config")).toBe("from-env.conf");
  });

  test("default applies when neither is present", () => {
    expect(parseArgs([], SPECS, { env: {} }).getString("config")).toBe("Ferrogate/Caddyfile");
  });

  test("an empty env value does not shadow the default", () => {
    expect(parseArgs([], SPECS, { env: { FERROGATE_CONFIG: "  " } }).getString("config")).toBe(
      "Ferrogate/Caddyfile",
    );
  });
});
