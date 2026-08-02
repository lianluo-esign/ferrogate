import type { WorkersAiClient } from "./adapters/workers_ai_llama_guard.js";
import { TIMED_OUT, withTimeout } from "./async.js";
/**
 * NATIVE PII DETECTION AND REDACTION — in-process, no external service (#680).
 *
 * ## Why this exists at all
 *
 * The only PII path this package shipped before was
 * `adapters/presidio.ts`: an HTTP client to a Python service the tenant has to
 * stand up and keep alive. On Workers that is a non-starter commercially, and
 * it is self-defeating operationally — the sensitive data has to LEAVE the
 * boundary in order to be told that it is sensitive.
 *
 * ## The design constraint, and the choice made against it
 *
 * Workers gives no Python, no ML runtime, and a CPU budget measured in
 * milliseconds. Three options were available:
 *
 * 1. **Patterns + validators** (chosen, always on). Deterministic, ~O(n) per
 *    entity over the selected text, no network, no tokens, no per-request cost
 *    beyond CPU. Catches exactly the entities that carry a CHECKSUM or a
 *    machine-checkable grammar — cards, IBANs, national ids, email, phone.
 *    Cannot catch a person's name, a street address or an employer, because
 *    those have no grammar to check.
 * 2. **Workers AI for everything.** One inference per screened request:
 *    hundreds of milliseconds, real token cost, and — decisively — a
 *    NON-DETERMINISTIC recall floor. A model that silently omits one of the
 *    three cards in a prompt has converted an open risk into a false assurance,
 *    which is strictly worse than not screening.
 * 3. **Hybrid** (chosen). The deterministic pack is the FLOOR and always runs.
 *    A Workers AI pass ({@link PiiAiStageConfig}) is available for the
 *    unstructured entities the pack provably cannot reach — and it is OFF
 *    unless a policy asks for it, because it changes the latency and cost
 *    profile of every request it touches.
 *
 * The hybrid's safety rule is {@link verbatimSpans}: a span the model returns is
 * accepted ONLY if it occurs byte-for-byte in the text that was screened. A
 * model that hallucinates a span cannot cause a redaction of bytes the user
 * never wrote, and cannot move a byte offset. It can still MISS — which is why
 * it never replaces the deterministic pack, only extends it.
 *
 * ## What this CANNOT catch (stated, not implied)
 *
 *  - Names, addresses, employers, dates of birth, free-text medical detail —
 *    unless the optional AI stage is enabled, and then only best-effort.
 *  - A card number a customer typed with a typo (Luhn rejects it — by design;
 *    the alternative is flagging every order number).
 *  - A 16-digit order number that happens to be Luhn-valid (`1234567812345670`
 *    is). Checksums bound false positives, they do not eliminate them.
 *  - Anything the ENVELOPE does not carry. A detector is only as complete as
 *    its extractor: see `envelope.ts` and the per-protocol coverage case in
 *    `test/pii.test.ts`.
 *  - PII split across two segments the coalescer does not join — it joins
 *    ADJACENT segments of the same source, which is what makes the streaming
 *    carry/delta window work; two different sources are still scanned apart.
 *
 * ## Evidence
 *
 * Same invariant as every other detector here: `matched_text` is NEVER set, and
 * the finding carries a KEYED `hmac-sha256:<hex>` fingerprint of the NORMALIZED
 * value, so `4111-1111-1111-1111` and `4111111111111111` correlate to one id
 * without either spelling reaching the audit trail. Logging the finding
 * verbatim would recreate the leak inside the evidence store, which is the one
 * place it is guaranteed to be retained.
 */
import { byteLen, byteMatchIndices, byteSlice } from "./bytes.js";
import {
  type ContentPatch,
  type ContentSource,
  type DetectorDescriptor,
  DetectorError,
  type DetectorHealth,
  type DetectorInput,
  type DetectorResult,
  DetectorSecret,
  type Finding,
  type FindingSeverity,
  type GuardrailDetector,
  MAX_DETECTOR_TIMEOUT_MS,
} from "./contract.js";
import {
  type CoalescedGroup,
  MAX_FINDINGS_PER_EVALUATION,
  coalesceSelectedSegments,
  isMutableTextSegment,
  regexByteMatches,
} from "./deterministic.js";
import type { ContentSegment } from "./envelope.js";
import { hmacSha256, toHex } from "./hash.js";

const PII_DETECTOR_VERSION = "pii/1";

// ---------------------------------------------------------------------------
// Entity vocabulary
// ---------------------------------------------------------------------------

/**
 * The deterministic entities. Every one has a CHECKSUM or a machine-checkable
 * grammar — that is the admission criterion for this list. An entity whose only
 * definition is "looks like it" belongs in the AI stage or nowhere, because a
 * pattern without a validator is a false-positive generator (a bare 16-digit
 * regex flags order numbers) and a false positive that redacts a customer's
 * order number is a correctness bug in THEIR application.
 */
export const PII_ENTITIES = [
  "credit_card",
  "iban",
  "us_ssn",
  "cn_resident_id",
  "email",
  "phone",
] as const;
export type PiiEntity = (typeof PII_ENTITIES)[number];

/** The unstructured entities only a model can reach. */
export const PII_AI_ENTITIES = ["person", "postal_address", "organization"] as const;
export type PiiAiEntity = (typeof PII_AI_ENTITIES)[number];

/** `pii.<entity>` — the finding category and the evidence key. */
export function piiEntityCategory(entity: PiiEntity | PiiAiEntity): string {
  return `pii.${entity}`;
}

/** `CREDIT_CARD` — the label a redaction placeholder carries. */
export function piiEntityLabel(entity: PiiEntity | PiiAiEntity): string {
  return entity.toUpperCase();
}

interface EntitySpec {
  /** Source strings for the scanning regexes (all `g`-compiled once). */
  readonly patterns: readonly string[];
  readonly severity: FindingSeverity;
  readonly confidence: number;
  /** Canonical form used for the keyed fingerprint (and for the validator). */
  normalize(raw: string): string;
  validate(normalized: string): boolean;
  /**
   * Right-trimmed candidates to try, longest first. Only `credit_card` needs
   * this: a grouped card followed by another number produces one greedy match
   * spanning both, and the correct answer is the longest PREFIX that passes
   * Luhn — not "no finding". Returning `[raw]` means "the match is the
   * candidate", which is right for every fixed-shape entity.
   */
  candidates?(raw: string): string[];
}

const DIGITS = /[0-9]/g;

function digitsOnly(value: string): string {
  return (value.match(DIGITS) ?? []).join("");
}

/** Luhn (ISO/IEC 7812-1) — the card-number check digit. */
export function luhnValid(digits: string): boolean {
  if (digits.length === 0) {
    return false;
  }
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let n = digits.charCodeAt(i) - 48;
    if (n < 0 || n > 9) {
      return false;
    }
    if (double) {
      n *= 2;
      if (n > 9) {
        n -= 9;
      }
    }
    sum += n;
    double = !double;
  }
  return sum % 10 === 0;
}

/** ISO 13616 IBAN check: move the first four chars to the end, mod 97 === 1. */
export function ibanValid(value: string): boolean {
  if (value.length < 15 || value.length > 34) {
    return false;
  }
  const rearranged = value.slice(4) + value.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    // A..Z → 10..35, expanded digit by digit so no value ever exceeds 2^53.
    const expanded = code >= 65 && code <= 90 ? String(code - 55) : ch;
    for (const digit of expanded) {
      const n = digit.charCodeAt(0) - 48;
      if (n < 0 || n > 9) {
        return false;
      }
      remainder = (remainder * 10 + n) % 97;
    }
  }
  return remainder === 1;
}

/**
 * SSA structural validity. There is no checksum, so these are the published
 * NEVER-ISSUED rules: area 000, 666 and 900-999 are not allocated, group 00 and
 * serial 0000 are never issued. They are what separates a real SSN shape from a
 * `123-00-4567` part number.
 */
export function usSsnValid(digits: string): boolean {
  if (digits.length !== 9) {
    return false;
  }
  const area = Number.parseInt(digits.slice(0, 3), 10);
  const group = Number.parseInt(digits.slice(3, 5), 10);
  const serial = Number.parseInt(digits.slice(5), 10);
  return area !== 0 && area !== 666 && area < 900 && group !== 0 && serial !== 0;
}

const CN_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2] as const;
const CN_CHECK = "10X98765432";

/** GB 11643-1999 resident identity card: ISO 7064 MOD 11-2, plus a real date. */
export function cnResidentIdValid(value: string): boolean {
  if (value.length !== 18) {
    return false;
  }
  let sum = 0;
  for (let i = 0; i < 17; i += 1) {
    const n = value.charCodeAt(i) - 48;
    if (n < 0 || n > 9) {
      return false;
    }
    sum += n * (CN_WEIGHTS[i] as number);
  }
  if (CN_CHECK[sum % 11] !== value[17]) {
    return false;
  }
  const year = Number.parseInt(value.slice(6, 10), 10);
  const month = Number.parseInt(value.slice(10, 12), 10);
  const day = Number.parseInt(value.slice(12, 14), 10);
  return year >= 1900 && year <= 2200 && month >= 1 && month <= 12 && day >= 1 && day <= 31;
}

function emailValid(value: string): boolean {
  const at = value.lastIndexOf("@");
  if (at <= 0 || at === value.length - 1) {
    return false;
  }
  const local = value.slice(0, at);
  const domain = value.slice(at + 1);
  if (local.length > 64 || local.startsWith(".") || local.endsWith(".") || local.includes("..")) {
    return false;
  }
  const labels = domain.split(".");
  if (labels.length < 2) {
    return false;
  }
  const tld = labels[labels.length - 1] as string;
  // A two-character minimum on the TLD is what rejects `a@b.c` and every
  // `file.js`-shaped token; `localhost` has no dot at all and dies above.
  if (tld.length < 2 || !/^[A-Za-z]+$/.test(tld)) {
    return false;
  }
  return labels.every((label) => label.length > 0 && label.length <= 63);
}

function phoneValid(digits: string): boolean {
  // E.164 allows 8..15 digits including the country code; NANP numbers arrive
  // here as 10 or 11 digits. Below 8 it is a short code or an extension, not a
  // subscriber number worth redacting.
  return digits.length >= 8 && digits.length <= 15 && digits[0] !== "0";
}

/**
 * Card shapes. Deliberately three EXACT spellings rather than one permissive
 * `[\d -]{13,25}` run: a permissive run swallows the neighbouring number, and
 * the greedy match then fails Luhn and yields NOTHING — a silent miss, the
 * failure mode this whole module is written against. {@link EntitySpec.candidates}
 * closes the remaining case where a grouped card is followed by more digits.
 */
const CARD_PATTERNS = ["\\b\\d{13,19}\\b", "\\b\\d{4}(?:[ -]\\d{2,6}){2,4}\\b"] as const;

const ENTITY_SPECS: Readonly<Record<PiiEntity, EntitySpec>> = {
  credit_card: {
    patterns: CARD_PATTERNS,
    severity: "critical",
    confidence: 0.99,
    normalize: digitsOnly,
    validate: (d) => d.length >= 13 && d.length <= 19 && luhnValid(d),
    candidates: (raw) => {
      const groups = raw.split(/([ -])/);
      const out: string[] = [];
      // Walk back one separated group at a time, longest first.
      for (let end = groups.length; end > 0; end -= 2) {
        const candidate = groups.slice(0, end).join("");
        if (digitsOnly(candidate).length >= 13) {
          out.push(candidate);
        }
      }
      return out.length > 0 ? out : [raw];
    },
  },
  iban: {
    patterns: ["\\b[A-Z]{2}\\d{2}[A-Z0-9]{11,30}\\b"],
    severity: "critical",
    confidence: 0.95,
    normalize: (raw) => raw.replace(/[ -]/g, "").toUpperCase(),
    validate: ibanValid,
  },
  us_ssn: {
    patterns: ["\\b\\d{3}[- ]\\d{2}[- ]\\d{4}\\b"],
    severity: "critical",
    confidence: 0.95,
    normalize: digitsOnly,
    validate: usSsnValid,
  },
  cn_resident_id: {
    patterns: ["\\b\\d{17}[0-9Xx]\\b"],
    severity: "critical",
    confidence: 0.97,
    normalize: (raw) => raw.toUpperCase(),
    validate: cnResidentIdValid,
  },
  email: {
    patterns: [
      "[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.){1,8}[A-Za-z]{2,24}\\b",
    ],
    severity: "high",
    confidence: 0.9,
    normalize: (raw) => raw.toLowerCase(),
    validate: emailValid,
  },
  phone: {
    patterns: [
      "\\+[1-9]\\d{7,14}\\b",
      "\\b(?:\\+?1[ .-])?\\(?[2-9]\\d{2}\\)?[ .-][2-9]\\d{2}[ .-]\\d{4}\\b",
    ],
    severity: "medium",
    confidence: 0.8,
    normalize: digitsOnly,
    validate: phoneValid,
  },
};

// ---------------------------------------------------------------------------
// Redaction policy
// ---------------------------------------------------------------------------

/**
 * How a detected value is replaced. REVERSIBILITY IS A POLICY CHOICE, never an
 * accident of which mode happened to be the default:
 *
 *  - `mask` — irreversible. `[REDACTED:CREDIT_CARD]`. Two different cards
 *    collapse to the same text; nothing downstream can tell them apart.
 *  - `pseudonymize` — irreversible but CORRELATABLE.
 *    `[CREDIT_CARD:hmac-sha256:<16 hex>]`, keyed by the same evidence key. The
 *    same value yields the same placeholder within a key, so an analyst can see
 *    "this is the same customer twice" without ever seeing the customer.
 *  - `tokenize` — REVERSIBLE, and only through the vault. The placeholder
 *    carries a RANDOM token (not a digest of the value), so the original is
 *    recoverable from the vault and from nothing else.
 */
export type PiiRedactionMode = "mask" | "pseudonymize" | "tokenize";

/** The sink a reversible redaction writes its token→value mapping into. */
export interface PiiTokenVault {
  store(token: string, original: string): void;
}

const TOKEN_PATTERN = /\[[A-Z_]+:(tok_[0-9a-f]{24})\]/g;

/**
 * An in-isolate vault. Adequate for a single request's lifetime, which is the
 * only scope a Worker has; a deployment that needs cross-request reversal
 * supplies its own {@link PiiTokenVault} backed by durable storage.
 */
export class InMemoryPiiTokenVault implements PiiTokenVault {
  #entries = new Map<string, string>();

  store(token: string, original: string): void {
    this.#entries.set(token, original);
  }

  reveal(token: string): string | undefined {
    return this.#entries.get(token);
  }

  get size(): number {
    return this.#entries.size;
  }

  /** Reverse every placeholder this vault issued; leave the others alone. */
  restore(text: string): string {
    return text.replace(TOKEN_PATTERN, (placeholder, token: string) => {
      return this.#entries.get(token) ?? placeholder;
    });
  }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Default Workers AI model for the optional unstructured-entity stage. */
export const PII_AI_DEFAULT_MODEL = "@cf/meta/llama-3.1-8b-instruct";

export interface PiiAiStageConfig {
  /** The Workers AI seam (`env.AI` or the REST client) — see the llama-guard adapter. */
  readonly client: WorkersAiClient;
  readonly model?: string;
  readonly entities: readonly PiiAiEntity[];
  readonly timeoutMs: number;
  /** Text handed to the model per evaluation; the rest is not sent. */
  readonly maxInputChars?: number;
}

export interface PiiDetectorConfig {
  id: string;
  supported_sources: ContentSource[];
  entities: PiiEntity[];
  redaction: PiiRedactionMode;
  /** Required for — and only for — `tokenize`. */
  vault?: PiiTokenVault;
  /** Mandatory: evidence fingerprints are keyed, never bare digests. */
  fingerprint_key: DetectorSecret;
  max_input_bytes?: number;
  ai?: PiiAiStageConfig;
}

function invalidConfig(message: string): DetectorError {
  return DetectorError.new("invalid_configuration", message);
}

function validateConfig(config: PiiDetectorConfig): void {
  if (config.id === undefined || config.id.trim().length === 0) {
    throw invalidConfig("pii Guardrail requires a non-empty id");
  }
  if (
    config.supported_sources === undefined ||
    config.supported_sources.length === 0 ||
    new Set(config.supported_sources).size !== config.supported_sources.length
  ) {
    throw invalidConfig("pii Guardrail sources must be non-empty and unique");
  }
  if (
    config.entities === undefined ||
    config.entities.length === 0 ||
    new Set(config.entities).size !== config.entities.length ||
    config.entities.some((e) => ENTITY_SPECS[e] === undefined)
  ) {
    throw invalidConfig("pii Guardrail entities must be non-empty, unique and known");
  }
  if (!(config.fingerprint_key instanceof DetectorSecret)) {
    // A PII detector without a key would have to emit either nothing (an
    // un-investigable finding) or a BARE digest of a short, low-entropy value —
    // an email or a card number is trivially recovered from an unkeyed SHA-256
    // by dictionary attack, which is the whole reason keying exists.
    throw invalidConfig("pii Guardrail requires fingerprint_secret_ref for keyed evidence");
  }
  if (config.redaction === "tokenize") {
    if (config.vault === undefined) {
      throw invalidConfig(
        "pii Guardrail reversible redaction (tokenize) requires an explicit token vault",
      );
    }
  } else if (config.vault !== undefined) {
    // An irreversible mode holding a vault would fill it with plaintext nobody
    // asked it to retain — reversibility by accident, in the direction that
    // creates a second copy of the data.
    throw invalidConfig("pii Guardrail vault is only valid with reversible (tokenize) redaction");
  }
  if (config.max_input_bytes === 0) {
    throw invalidConfig("pii Guardrail max_input_bytes must be greater than zero");
  }
  if (config.ai !== undefined) {
    const ai = config.ai;
    if (
      ai.entities.length === 0 ||
      new Set(ai.entities).size !== ai.entities.length ||
      ai.entities.some((e) => !PII_AI_ENTITIES.includes(e))
    ) {
      throw invalidConfig("pii Guardrail AI entities must be non-empty, unique and known");
    }
    if (ai.timeoutMs <= 0 || ai.timeoutMs > MAX_DETECTOR_TIMEOUT_MS) {
      throw invalidConfig("pii Guardrail AI timeout is invalid or exceeds the runtime ceiling");
    }
    if (typeof ai.client?.run !== "function") {
      throw invalidConfig("pii Guardrail AI stage requires a Workers AI client");
    }
  }
}

// ---------------------------------------------------------------------------
// Scan sink
// ---------------------------------------------------------------------------

interface EntityMatch {
  readonly category: string;
  readonly severity: FindingSeverity;
  readonly confidence: number;
  readonly label: string;
  /** Canonical value — fingerprinted and (for `tokenize`) vaulted. Never emitted. */
  readonly normalized: string;
  readonly start: number;
  readonly end: number;
}

class PiiSink {
  findings: Finding[] = [];
  patches: ContentPatch[] = [];
  seen = new Set<string>();
  patched = new Map<string, Array<[number, number]>>();
  truncated = false;
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

export class PiiDetector implements GuardrailDetector {
  readonly #config: PiiDetectorConfig;
  readonly #specs: Array<[PiiEntity, EntitySpec]>;

  private constructor(config: PiiDetectorConfig) {
    this.#config = config;
    // Fixed iteration order (the declared PII_ENTITIES order) so that when two
    // entities can claim overlapping bytes the winner is deterministic and the
    // same on every isolate — an evidence id that depends on scan order is not
    // an evidence id.
    this.#specs = PII_ENTITIES.filter((e) => config.entities.includes(e)).map((e) => [
      e,
      ENTITY_SPECS[e],
    ]);
  }

  static new(config: PiiDetectorConfig): PiiDetector {
    validateConfig(config);
    for (const [, spec] of Object.entries(ENTITY_SPECS)) {
      for (const pattern of spec.patterns) {
        // Compiled here so a pattern-pack edit that does not compile is a build
        // error at construction, not a 500 on the first request that hits it.
        new RegExp(pattern, "g");
      }
    }
    return new PiiDetector(config);
  }

  descriptor(): DetectorDescriptor {
    return {
      id: this.#config.id,
      version: PII_DETECTOR_VERSION,
      supports_request: true,
      supports_response: true,
      supports_transform: true,
      supported_sources: [...this.#config.supported_sources],
      credential: "none",
      // The deterministic pack never leaves the isolate. The AI stage reaches
      // Workers AI, which is Cloudflare-operated but not in-repo — saying
      // otherwise on a residency field would be a compliance lie.
      data_residency: this.#config.ai !== undefined ? "provider_saas" : "in_repo",
      max_payload_bytes: this.#config.max_input_bytes ?? Number.MAX_SAFE_INTEGER,
      declared_failure_modes:
        this.#config.ai !== undefined
          ? ["timeout", "unavailable", "invalid_response", "internal", "invalid_configuration"]
          : ["timeout", "internal", "invalid_configuration"],
    };
  }

  health(): DetectorHealth {
    return {
      circuit_open: false,
      consecutive_failures: 0,
      in_flight: 0,
      request_total: 0,
      success_total: 0,
      failure_total: 0,
    };
  }

  async evaluate(input: DetectorInput, deadlineMs: number): Promise<DetectorResult> {
    if (Date.now() >= deadlineMs) {
      throw DetectorError.new("timeout", "pii Guardrail deadline expired before execution");
    }
    const selected = input.segments.filter((s) =>
      this.#config.supported_sources.includes(s.source),
    );
    const sink = new PiiSink();

    if (
      this.#config.max_input_bytes !== undefined &&
      selected.reduce((acc, s) => acc + byteLen(s.text), 0) > this.#config.max_input_bytes
    ) {
      // Fail closed and emit NO covering patch: an oversized payload is
      // unredactable, so a `redact` action must not be able to claim success.
      sink.findings.push(
        this.#finding("size.input_bytes", "high", 1.0, undefined, undefined, undefined),
      );
    }

    const groups = coalesceSelectedSegments(selected);

    // (a) The COALESCED scan. Two adjacent same-source segments are joined
    //     before matching, which is what catches a card straddling a streaming
    //     chunk boundary (`apps/gateway/src/guardrails/stream.ts` builds exactly
    //     that carry+delta pair). Without it a value split as `41111111` |
    //     `11111111` is two harmless digit runs and the leak goes out clean.
    for (const group of groups) {
      for (const match of this.#scanText(group.text)) {
        this.#addGroupMatch(sink, group, match);
      }
    }
    // (b) The PER-SEGMENT rescan restores `\b`/anchor context inside each part,
    //     which the join blurs. Findings dedupe by (category, segment, range).
    for (const segment of selected) {
      for (const match of this.#scanText(segment.text)) {
        this.#addMatch(sink, segment, match);
      }
    }

    if (this.#config.ai !== undefined) {
      for (const group of groups) {
        for (const match of await this.#scanWithAi(
          this.#config.ai,
          group.text,
          input,
          deadlineMs,
        )) {
          this.#addGroupMatch(sink, group, match);
        }
      }
    }

    return {
      verdict: sink.findings.length === 0 ? "pass" : "fail",
      findings: sink.findings,
      patches: sink.patches,
      detector_version: PII_DETECTOR_VERSION,
    };
  }

  // -- scanning -------------------------------------------------------------

  /** Every validated entity occurrence in `text`, as UTF-8 byte ranges. */
  #scanText(text: string): EntityMatch[] {
    const out: EntityMatch[] = [];
    for (const [entity, spec] of this.#specs) {
      const accepted: Array<[number, number]> = [];
      for (const pattern of spec.patterns) {
        for (const [start, end] of regexByteMatches(pattern, text)) {
          const raw = byteSlice(text, start, end);
          if (raw === undefined) {
            continue;
          }
          const candidates = spec.candidates ? spec.candidates(raw) : [raw];
          for (const candidate of candidates) {
            const normalized = spec.normalize(candidate);
            if (!spec.validate(normalized)) {
              continue;
            }
            const candidateEnd = start + byteLen(candidate);
            // One entity may not claim the same bytes twice (the bare and the
            // grouped card patterns overlap on some inputs).
            if (accepted.some(([s, e]) => start < e && s < candidateEnd)) {
              break;
            }
            accepted.push([start, candidateEnd]);
            out.push({
              category: piiEntityCategory(entity),
              severity: spec.severity,
              confidence: spec.confidence,
              label: piiEntityLabel(entity),
              normalized,
              start,
              end: candidateEnd,
            });
            break;
          }
        }
      }
    }
    return out;
  }

  // -- sink -----------------------------------------------------------------

  #addGroupMatch(sink: PiiSink, group: CoalescedGroup, match: EntityMatch): void {
    group.segments.forEach((segment, index) => {
      const segmentStart = group.starts[index] as number;
      const segmentEnd = segmentStart + byteLen(segment.text);
      const overlapStart = Math.max(match.start, segmentStart);
      const overlapEnd = Math.min(match.end, segmentEnd);
      if (overlapStart < overlapEnd) {
        this.#addMatch(sink, segment, {
          ...match,
          start: overlapStart - segmentStart,
          end: overlapEnd - segmentStart,
        });
      }
    });
  }

  #addMatch(sink: PiiSink, segment: ContentSegment, match: EntityMatch): void {
    if (sink.truncated) {
      return;
    }
    if (sink.findings.length >= MAX_FINDINGS_PER_EVALUATION) {
      sink.truncated = true;
      sink.findings.push(
        this.#finding("detector.truncated", "critical", 1.0, segment, [0, 0], undefined),
      );
      return;
    }
    const key = `${match.category} ${segment.segment_id} ${match.start} ${match.end}`;
    if (!sink.seen.has(key)) {
      sink.seen.add(key);
      sink.findings.push(
        this.#finding(
          match.category,
          match.severity,
          match.confidence,
          segment,
          [match.start, match.end],
          match.normalized,
        ),
      );
    }
    if (!isMutableTextSegment(segment)) {
      return;
    }
    const intervals = sink.patched.get(segment.segment_id) ?? [];
    if (intervals.some(([s, e]) => match.start < e && s < match.end)) {
      return;
    }
    intervals.push([match.start, match.end]);
    sink.patched.set(segment.segment_id, intervals);
    sink.patches.push({
      segment_id: segment.segment_id,
      expected_fingerprint: segment.fingerprint,
      protocol_location: segment.protocol_location,
      byte_start: match.start,
      byte_end: match.end,
      replacement: this.#replacement(match),
    });
  }

  /**
   * The placeholder. Every mode's output is drawn from `[A-Z0-9_:\[\]-]`, which
   * contains no `"`, no `\` and no control character — so substituting it INSIDE
   * a JSON string (a tool result whose text is itself a JSON document, an
   * Anthropic `partial_json` delta) leaves the document parseable. A naive
   * `<redacted "value">` placeholder would turn every such redaction into a
   * downstream parse error.
   */
  #replacement(match: EntityMatch): string {
    switch (this.#config.redaction) {
      case "mask":
        return `[REDACTED:${match.label}]`;
      case "pseudonymize":
        return `[${match.label}:hmac-sha256:${this.#digest(match.normalized).slice(0, 16)}]`;
      case "tokenize": {
        // RANDOM, not derived: a token derived from the value would be
        // reversible by anyone who can guess the value, which defeats the point
        // of gating reversal on the vault.
        const bytes = new Uint8Array(12);
        crypto.getRandomValues(bytes);
        const token = `tok_${toHex(bytes)}`;
        (this.#config.vault as PiiTokenVault).store(token, match.normalized);
        return `[${match.label}:${token}]`;
      }
    }
  }

  #digest(value: string): string {
    return toHex(
      hmacSha256(this.#config.fingerprint_key.asBytes(), new TextEncoder().encode(value)),
    );
  }

  #finding(
    category: string,
    severity: FindingSeverity,
    confidence: number | null,
    segment: ContentSegment | undefined,
    range: [number, number] | undefined,
    sensitiveValue: string | undefined,
  ): Finding {
    return {
      category,
      severity,
      confidence,
      byte_start: range ? range[0] : null,
      byte_end: range ? range[1] : null,
      segment_id: segment ? segment.segment_id : null,
      fingerprint:
        sensitiveValue !== undefined ? `hmac-sha256:${this.#digest(sensitiveValue)}` : null,
      // NEVER the matched text. An audit row that quotes the value it caught has
      // moved the leak into the one store guaranteed to retain it.
      matched_text: null,
      attributes: {
        detector: "pii",
        redaction: this.#config.redaction,
      },
    };
  }

  // -- optional Workers AI stage -------------------------------------------

  async #scanWithAi(
    ai: PiiAiStageConfig,
    text: string,
    input: DetectorInput,
    deadlineMs: number,
  ): Promise<EntityMatch[]> {
    const budget = Math.min(ai.timeoutMs, Math.max(0, deadlineMs - Date.now()));
    if (budget <= 0) {
      throw DetectorError.new("timeout", "pii Guardrail AI stage had no time budget left");
    }
    const excerpt = text.slice(0, ai.maxInputChars ?? 4_000);
    if (excerpt.trim().length === 0) {
      return [];
    }
    let raw: unknown;
    try {
      const settled = await withTimeout(
        ai.client.run(
          ai.model ?? PII_AI_DEFAULT_MODEL,
          aiRequest(excerpt, ai.entities),
          input.tenant.organization_id,
        ),
        budget,
      );
      if (settled === TIMED_OUT) {
        throw DetectorError.new("timeout", "pii Guardrail AI stage timed out");
      }
      raw = settled;
    } catch (error) {
      if (error instanceof DetectorError) {
        throw error;
      }
      // Fail-closed: never degrade an unreachable model to a clean pass. The
      // policy's `on_error` decides whether that blocks or allows.
      throw DetectorError.new("unavailable", "pii Guardrail AI stage was unavailable");
    }
    return this.#aiMatches(text, raw, ai.entities);
  }

  #aiMatches(text: string, raw: unknown, allowed: readonly PiiAiEntity[]): EntityMatch[] {
    const spans = parseAiSpans(raw);
    const out: EntityMatch[] = [];
    const seen = new Set<string>();
    for (const span of spans) {
      if (!allowed.includes(span.type)) {
        continue;
      }
      for (const start of verbatimSpans(text, span.text)) {
        const key = `${span.type} ${start}`;
        if (seen.has(key)) {
          continue;
        }
        seen.add(key);
        out.push({
          category: piiEntityCategory(span.type),
          severity: "high",
          // Lower than any checksum-validated entity, and honestly so: this is a
          // model's opinion, not an arithmetic fact.
          confidence: 0.6,
          label: piiEntityLabel(span.type),
          normalized: span.text,
          start,
          end: start + byteLen(span.text),
        });
      }
    }
    return out;
  }
}

// ---------------------------------------------------------------------------
// Policy definition → detector config
// ---------------------------------------------------------------------------

/** The `kind: "pii"` shape, structurally — `policy.ts` imports THIS, not vice versa. */
export interface PiiPolicyDefinition {
  readonly entities: readonly PiiEntity[];
  readonly redaction: PiiRedactionMode;
  readonly max_input_bytes?: number | null | undefined;
  readonly ai?:
    | {
        readonly model: string;
        readonly entities: readonly PiiAiEntity[];
        readonly timeout_ms: number;
        readonly max_input_chars: number;
      }
    | null
    | undefined;
}

/** What the HOST environment can supply that a policy document cannot name. */
export interface PiiHostCapabilities {
  readonly vault?: PiiTokenVault | undefined;
  readonly workersAi?: WorkersAiClient | undefined;
}

/**
 * Translate a policy definition into a detector config, ONCE.
 *
 * Two build sites construct detectors from a `DetectorDefinition`
 * (`binding.ts`, for MCP/agent-runtime, and `apps/gateway/src/guardrails/detectors.ts`),
 * and a PII detector is the wrong thing to translate twice: the two sites would
 * be free to disagree about what happens when the host cannot satisfy the
 * policy, and one of them would answer "build it anyway, weaker".
 *
 * Both host gaps below therefore raise, rather than degrade:
 *
 *  - `tokenize` with no vault would become IRREVERSIBLE. An operator who chose
 *    reversible redaction and silently got irreversible redaction has lost data
 *    they believed was recoverable, and nothing in the response says so.
 *  - an `ai` stage with no Workers AI transport would quietly drop the only
 *    layer that reaches names and addresses, leaving a policy that claims to
 *    detect them and does not. Unlike `workers_ai_llama_guard` — whose graceful
 *    disable removes the WHOLE check, visibly — a half-built PII detector still
 *    returns `pass` on a name, which reads as "screened and clean".
 */
export function piiDetectorConfig(
  id: string,
  definition: PiiPolicyDefinition,
  supportedSources: ContentSource[],
  fingerprintKey: DetectorSecret,
  host: PiiHostCapabilities,
  buildError: (message: string) => Error,
): PiiDetectorConfig {
  if (definition.redaction === "tokenize" && host.vault === undefined) {
    throw buildError(
      "pii detector requests reversible (tokenize) redaction but no token vault is configured",
    );
  }
  const ai = definition.ai;
  if (ai !== null && ai !== undefined && host.workersAi === undefined) {
    throw buildError(
      "pii detector requests the Workers AI stage but no Workers AI transport is configured",
    );
  }
  return {
    id,
    supported_sources: supportedSources,
    entities: [...definition.entities],
    redaction: definition.redaction,
    fingerprint_key: fingerprintKey,
    ...(host.vault !== undefined && definition.redaction === "tokenize"
      ? { vault: host.vault }
      : {}),
    ...(definition.max_input_bytes !== null && definition.max_input_bytes !== undefined
      ? { max_input_bytes: definition.max_input_bytes }
      : {}),
    ...(ai !== null && ai !== undefined
      ? {
          ai: {
            client: host.workersAi as WorkersAiClient,
            model: ai.model,
            entities: [...ai.entities],
            timeoutMs: ai.timeout_ms,
            maxInputChars: ai.max_input_chars,
          },
        }
      : {}),
  };
}

// ---------------------------------------------------------------------------
// Workers AI wire shape
// ---------------------------------------------------------------------------

interface AiSpan {
  readonly type: PiiAiEntity;
  readonly text: string;
}

/** The instruction. JSON-only, verbatim spans, no explanation. */
function aiRequest(text: string, entities: readonly PiiAiEntity[]): unknown {
  return {
    messages: [
      {
        role: "system",
        content: [
          "You extract personal data from text. Reply with ONLY a JSON object",
          'of the form {"entities":[{"type":"<type>","text":"<exact substring>"}]}.',
          `Allowed types: ${entities.join(", ")}.`,
          "Copy each span EXACTLY as it appears in the input; never paraphrase,",
          'translate or invent one. If there is nothing to report, reply {"entities":[]}.',
        ].join(" "),
      },
      { role: "user", content: text },
    ],
    max_tokens: 512,
  };
}

/**
 * Pull spans out of whatever the model produced. A model that answers with prose
 * around its JSON is normal, so the first balanced `{...}` is taken; anything
 * that still will not parse yields NO spans rather than an exception, because
 * the deterministic pack has already run and its findings must survive a chatty
 * model.
 */
function parseAiSpans(raw: unknown): AiSpan[] {
  const response =
    typeof raw === "string"
      ? raw
      : typeof (raw as { response?: unknown } | null)?.response === "string"
        ? (raw as { response: string }).response
        : undefined;
  if (response === undefined) {
    return [];
  }
  const start = response.indexOf("{");
  const end = response.lastIndexOf("}");
  if (start < 0 || end <= start) {
    return [];
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(response.slice(start, end + 1));
  } catch {
    return [];
  }
  const entities = (parsed as { entities?: unknown } | null)?.entities;
  if (!Array.isArray(entities)) {
    return [];
  }
  const out: AiSpan[] = [];
  for (const entry of entities) {
    const type = (entry as { type?: unknown } | null)?.type;
    const text = (entry as { text?: unknown } | null)?.text;
    if (
      typeof type === "string" &&
      typeof text === "string" &&
      // A one-character "span" would redact every occurrence of a letter; a
      // 200-character one is the model echoing the prompt back.
      text.length >= 2 &&
      text.length <= 128 &&
      (PII_AI_ENTITIES as readonly string[]).includes(type)
    ) {
      out.push({ type: type as PiiAiEntity, text });
    }
  }
  return out;
}

/**
 * Byte offsets at which `span` occurs VERBATIM in `text`, or none.
 *
 * This is the safety rule that makes a probabilistic stage usable at all: the
 * model proposes, the text disposes. A hallucinated span — a name the model
 * inferred, a value it "corrected", a translation — matches nothing and is
 * dropped, so it can neither produce a finding nor move a byte range. Offsets
 * are computed here rather than trusted from the model for the same reason.
 */
export function verbatimSpans(text: string, span: string): number[] {
  return span.length === 0 ? [] : byteMatchIndices(text, span);
}
