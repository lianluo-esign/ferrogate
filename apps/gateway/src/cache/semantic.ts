/**
 * The SEMANTIC response cache — Rust `SemanticResponseCache`
 * (`crates/ferrogate-gateway/src/semantic_cache.rs`, issue #273).
 *
 * ## Why this file exists, and what the marker it closes got wrong
 *
 * `cache/config.ts` and `cache/metrics.ts` both carried a PORT-TODO saying the
 * semantic layer "maps to **Vectorize + Workers AI** on this platform" and was
 * therefore blocked on two bindings this agent may not declare. That reading
 * was wrong, and it is worth stating why so the same mistake is not made again:
 * it was inferred from the WORDS "embedding" and "cosine similarity" rather
 * than from the Rust. The Rust file's own header says the opposite —
 *
 *   > In-tree cosine similarity over stored f32 vectors; no external vector DB.
 *
 * — and `embed_text` is a deterministic, network-free **feature-hashing**
 * embedder: tokens are lowercased, FNV-1a-64 hashed into a fixed 256-dimension
 * signed bag-of-words vector, and L2-normalized. There is no model, no
 * inference call and no vector database anywhere in it. It is arithmetic over
 * the prompt string, which ports to a Worker exactly, and every value below is
 * the Rust value: 256 dims, the same FNV-1a-64 constants, the same signed
 * hashing rule (the top bit picks the sign), the same Unicode-alphanumeric
 * tokenizer, the same ASCII-only lowercasing.
 *
 * ## The ONE thing that genuinely does not port — and it is kept, not closed
 *
 * PORT-TODO(L: inventory-request-path §1.7 "Caches", issue #273): **PLATFORM
 * LIMIT on the STORE's REACH, not on the algorithm.** Rust held one
 * `SemanticResponseCache` in `AppState` — a single process, so every request
 * the deployment served saw every entry. A Worker has no process. The exact
 * layer solves this with the **Cache API**, which is colo-shared, but the Cache
 * API can only answer "is this exact key present"; a nearest-neighbour lookup
 * over stored vectors is not something it (or KV, or R2) can express. The two
 * reachable shared forms are both out of this slice's hands and both cost more
 * than they return here:
 *
 *   - a **Durable Object** holding the vectors would make one object a
 *     serialization point on the read path of every cacheable request in the
 *     deployment — the opposite of what a cache is for — and needs a
 *     `[[durable_objects]]` binding + a `new_sqlite_classes` migration in
 *     `wrangler.toml`, which the integrate step owns;
 *   - **Vectorize** is the product built for it, and `apps/gateway/wrangler.toml`
 *     has no `[[vectorize]]` stanza; adding one is likewise not this agent's.
 *
 * So the shipped approximation, stated exactly: {@link sharedSemanticCache}
 * is a MODULE-SCOPE singleton, i.e. **per-isolate**. Within one isolate it
 * behaves precisely as the Rust process-global did — entries persist across
 * requests, TTL and `max_records` are the Rust ones, scope isolation is the
 * Rust one. Across isolates it does not: a paraphrase that lands on a cold
 * isolate misses and is dispatched upstream. That is a HIT-RATE difference, and
 * only a hit-rate difference — it can never serve a wrong body, because the
 * scope bucket (below) carries the identical tenant/credential/policy material
 * the exact key does. `test/cache/semantic.test.ts` pins both halves: the
 * within-isolate sharing that IS implemented, and the cross-store isolation
 * that stands in for the cross-isolate residue.
 *
 * ## The scope bucket is the whole isolation story
 *
 * Rust bucketed on `ai_semantic_scope_hash` — every field of the exact cache
 * key EXCEPT the request body. This port does the same, over this tree's field
 * set (`cache/key.ts`'s, including the three ADDED credential-identity fields),
 * and hashes it with **SHA-256 rather than FNV-1a-64** for the reason
 * `cache/key.ts` gives at length: FNV-1a is linear and trivially collidable,
 * and a collided bucket here is a cross-tenant body disclosure. Rust could
 * afford FNV because a Rust `HashMap` bucket collision still compares the full
 * key; a digest-addressed bucket has nothing left to compare.
 */
import type { CachedResponse } from "./store.js";

/** Rust `SEMANTIC_EMBED_DIMS`. Fixed so every vector is directly comparable. */
export const SEMANTIC_EMBED_DIMS = 256;

/**
 * FNV-1a-64 over `bytes`, as its two 32-bit halves.
 *
 * Rust ran this in `u64`. JavaScript has no `u64`, and `BigInt` would be exact
 * but allocates per operation — this runs once per TOKEN of a prompt that may
 * be up to `MAX_CACHEABLE_BODY_BYTES` (1 MiB), so the allocation is on the hot
 * path of every cacheable request. The 32-bit-halves form below is exact
 * instead of approximate: the prime is `0x0000_0100_0000_01b3`, so every
 * partial product (`lo * 0x1b3`, `lo * 0x100`, `hi * 0x1b3`) is under 2^41 and
 * therefore integral in a float64, and `>>> 0` is ToUint32, i.e. exactly the
 * `wrapping_mul` truncation Rust performs.
 */
export function fnv1a64(bytes: Uint8Array): { hi: number; lo: number } {
  // 0xcbf2_9ce4_8422_2325
  let hi = 0xcbf29ce4;
  let lo = 0x84222325;
  for (const byte of bytes) {
    // Rust `hash ^= u64::from(byte)` — only the low byte can change.
    lo = (lo ^ byte) >>> 0;
    const lowProduct = lo * 0x1b3;
    const carry = Math.floor(lowProduct / 0x100000000);
    const nextLo = lowProduct >>> 0;
    hi = (hi * 0x1b3 + lo * 0x100 + carry) >>> 0;
    lo = nextLo;
  }
  return { hi, lo };
}

/**
 * Rust `embed_text`: a deterministic, network-free feature-hashing embedder.
 *
 * Tokens are split on non-alphanumerics, ASCII-lowercased, FNV-1a-64 hashed
 * into one of {@link SEMANTIC_EMBED_DIMS} buckets, accumulated with a SIGN
 * taken from the hash's top bit (so colliding tokens partially cancel instead
 * of always reinforcing), then L2-normalized.
 *
 * Two mappings deserve naming because a lazy version of either would silently
 * change the vector:
 *
 *  - the tokenizer is `char::is_alphanumeric`, i.e. Unicode Alphabetic ∪ N, not
 *    `[a-zA-Z0-9]`. `/[^\p{Alphabetic}\p{N}]+/u` is that set;
 *  - the lowercasing is `to_ascii_lowercase`, which leaves every non-ASCII
 *    character ALONE. `String.prototype.toLowerCase()` is full Unicode and
 *    would fold e.g. `İ` differently, so only `A-Z` is mapped.
 *
 * Accumulation uses `Math.fround` because Rust accumulated in `f32`. Without
 * it a borderline pair could land on the other side of the configured
 * threshold than the Rust would have put it.
 *
 * ## Cost, measured rather than assumed
 *
 * This runs per cacheable request over a prompt bounded by
 * `MAX_CACHEABLE_BODY_BYTES` (1 MiB), so it was benchmarked before being put on
 * that path: **~33 ms for a full 1 MiB of prose**, against ~12 ms for the
 * SHA-256 the exact layer already computes over the same bytes. Same order of
 * magnitude as work the request was doing anyway, and far inside a Worker's CPU
 * budget — so the prompt is NOT truncated before embedding, which would have
 * silently changed the vector away from the Rust one.
 */
export function embedText(text: string): Float32Array {
  const vector = new Float32Array(SEMANTIC_EMBED_DIMS);
  const encoder = new TextEncoder();
  for (const token of text.split(TOKEN_SEPARATOR)) {
    if (token === "") continue;
    const lowered = token.replace(/[A-Z]/g, asciiLower);
    const hash = fnv1a64(encoder.encode(lowered));
    // `hash % 256`: 256 divides 2^32, so the low byte of the low half IS the
    // remainder of the full 64-bit value.
    const index = hash.lo & 0xff;
    // `(hash >> 63) & 1` — the top bit of the high half.
    const sign = hash.hi >>> 31 === 1 ? -1 : 1;
    vector[index] = Math.fround((vector[index] as number) + sign);
  }
  let norm = 0;
  for (const value of vector) norm = Math.fround(norm + Math.fround(value * value));
  norm = Math.fround(Math.sqrt(norm));
  if (norm > 0) {
    for (let at = 0; at < vector.length; at += 1) {
      vector[at] = Math.fround((vector[at] as number) / norm);
    }
  }
  return vector;
}

const TOKEN_SEPARATOR = /[^\p{Alphabetic}\p{N}]+/u;

function asciiLower(character: string): string {
  return String.fromCharCode(character.charCodeAt(0) + 32);
}

/**
 * Rust `cosine_similarity`.
 *
 * Returns `0.0` for length-mismatched or zero-magnitude inputs, which Rust
 * documents as fail-safe: a degenerate vector must never produce a HIT. Note
 * that `0.0` is below every valid threshold — the config range is `(0.0, 1.0]`
 * precisely so a threshold of `0` (which would make every degenerate pair a
 * hit) cannot be configured.
 */
export function cosineSimilarity(a: Float32Array, b: Float32Array): number {
  if (a.length !== b.length) return 0;
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let at = 0; at < a.length; at += 1) {
    const left = a[at] as number;
    const right = b[at] as number;
    dot = Math.fround(dot + Math.fround(left * right));
    normA = Math.fround(normA + Math.fround(left * left));
    normB = Math.fround(normB + Math.fround(right * right));
  }
  if (normA === 0 || normB === 0) return 0;
  return Math.fround(
    dot / Math.fround(Math.fround(Math.sqrt(normA)) * Math.fround(Math.sqrt(normB))),
  );
}

/**
 * Rust `prompt_text_for_embedding`: the natural-language text an embedding is
 * computed over.
 *
 * Handles OpenAI-style `messages[].content` (a string, or a content-part array
 * whose parts may be `{text}` objects or bare strings), the Responses `input`
 * field, and a bare `prompt`, in that precedence order — each tried only when
 * the ones before it produced nothing but whitespace. The final fallback is the
 * whole serialized body, so an embedding is ALWAYS produced and an unrecognised
 * request shape degrades to "similar only to a near-identical body" rather than
 * to "similar to everything" (which an empty string would do: every empty
 * vector is zero-magnitude, and `cosineSimilarity` answers 0 for those, so it
 * would actually degrade to "similar to nothing" — still not a shape worth
 * relying on).
 *
 * `canonicalJson` stands in for `serde_json::Value::to_string`, whose map is a
 * `BTreeMap` and therefore already key-sorted.
 */
export function promptTextForEmbedding(
  body: unknown,
  serialize: (value: unknown) => string,
): string {
  const record = isRecord(body) ? body : {};
  const parts: string[] = [];

  const messages = record.messages;
  if (Array.isArray(messages)) {
    for (const message of messages) {
      appendContentText(isRecord(message) ? message.content : undefined, parts);
    }
  }

  if (joined(parts).trim() === "" && record.input !== undefined) {
    appendContentText(record.input, parts);
  }

  if (joined(parts).trim() === "" && typeof record.prompt === "string") {
    parts.push(record.prompt);
  }

  const collected = joined(parts);
  if (collected.trim() === "") return serialize(body);
  return collected;
}

function joined(parts: readonly string[]): string {
  return parts.join("\n");
}

function appendContentText(content: unknown, out: string[]): void {
  if (typeof content === "string") {
    out.push(content);
    return;
  }
  if (!Array.isArray(content)) return;
  for (const part of content) {
    if (isRecord(part) && typeof part.text === "string") {
      out.push(part.text);
    } else if (typeof part === "string") {
      out.push(part);
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Rust `SemanticCacheContext` — the scope bucket plus the prompt embedding. */
export interface SemanticCacheContext {
  readonly scope: string;
  readonly embedding: Float32Array;
}

/** What a lookup found, and how close it was. */
export interface SemanticCacheHit {
  readonly response: CachedResponse;
  readonly similarity: number;
}

interface SemanticEntry {
  readonly seq: number;
  readonly embedding: Float32Array;
  readonly response: CachedResponse;
  readonly expiresAtUnix: number;
}

/**
 * The isolate memory this cache is allowed to hold in RESPONSE BODIES.
 *
 * **This bound is not in the Rust, and it is the one place this port must not
 * be faithful.** Rust's `max_records` default is 1000 and the entry holds the
 * whole `AiCachedResponse`; `MAX_CACHEABLE_BODY_BYTES` admits a body up to 1
 * MiB. 1000 × 1 MiB is ~1 GB, in a process that had gigabytes. A Workers
 * isolate has **128 MiB**, and exceeding it is not a slow cache — it is the
 * isolate being killed, i.e. an outage caused by a cache.
 *
 * The exact-match layer has no such exposure: its store is the Cache API, which
 * lives outside the isolate. Only this one holds bodies in memory, so only this
 * one needs the bound.
 *
 * 8 MiB is deliberately conservative — a chat completion is a few KB, so this
 * is hundreds to thousands of realistic entries, while capping the damage a
 * pathological 1 MiB-response workload can do at 8 of them. `max_records`
 * still applies; whichever bound binds first evicts, and both evict in the same
 * global FIFO order, so the Rust eviction ORDER is unchanged.
 */
export const SEMANTIC_CACHE_MAX_BYTES = 8 * 1024 * 1024;

/**
 * Rust `SemanticResponseCache`, structure for structure.
 *
 * `scopes` is the `HashMap<u64, Vec<Entry>>`; `order` is the
 * `VecDeque<(scope, seq)>` that gives eviction a GLOBAL FIFO independent of
 * which bucket an entry sits in, so one busy tenant cannot pin another's
 * entries past `max_records`.
 */
export class SemanticResponseCache {
  readonly #scopes = new Map<string, SemanticEntry[]>();
  readonly #order: Array<{ scope: string; seq: number }> = [];
  readonly #maxBytes: number;
  #seqCounter = 0;
  #total = 0;
  #bytes = 0;

  constructor(options: { maxBytes?: number } = {}) {
    this.#maxBytes = options.maxBytes ?? SEMANTIC_CACHE_MAX_BYTES;
  }

  /** Live entry count. For the TTL/cap assertions. */
  get size(): number {
    return this.#total;
  }

  /** Response bytes currently held. For the memory-bound assertions. */
  get byteSize(): number {
    return this.#bytes;
  }

  /**
   * The highest-similarity LIVE entry in `scope` at or above `threshold`.
   *
   * Expired entries are skipped rather than removed — Rust reclaims them
   * lazily through the insertion cap and never serves one — and ties keep the
   * FIRST best (Rust's `similarity > best_sim`, strictly greater).
   */
  lookup(
    scope: string,
    embedding: Float32Array,
    threshold: number,
    nowUnix: number,
  ): SemanticCacheHit | undefined {
    const entries = this.#scopes.get(scope);
    if (entries === undefined) return undefined;
    let best: SemanticCacheHit | undefined;
    for (const entry of entries) {
      if (entry.expiresAtUnix <= nowUnix) continue;
      const similarity = cosineSimilarity(embedding, entry.embedding);
      if (similarity >= threshold && (best === undefined || similarity > best.similarity)) {
        best = { response: entry.response, similarity };
      }
    }
    return best;
  }

  /** Rust `insert` — same TTL and same global record cap as the exact store. */
  insert(
    scope: string,
    embedding: Float32Array,
    response: CachedResponse,
    ttlSeconds: number,
    maxRecords: number,
    nowUnix: number,
  ): void {
    if (ttlSeconds <= 0 || maxRecords <= 0) return;
    // A single body that cannot fit the isolate budget is REFUSED rather than
    // admitted-then-evicted: admitting it would flush every other entry on its
    // way out, so one oversized response would empty the cache.
    if (response.body.byteLength > this.#maxBytes) return;
    this.#seqCounter += 1;
    const seq = this.#seqCounter;
    const bucket = this.#scopes.get(scope);
    const entry: SemanticEntry = {
      seq,
      embedding,
      response,
      expiresAtUnix: nowUnix + ttlSeconds,
    };
    if (bucket === undefined) this.#scopes.set(scope, [entry]);
    else bucket.push(entry);
    this.#order.push({ scope, seq });
    this.#total += 1;
    this.#bytes += response.body.byteLength;
    this.#evictToCap(maxRecords);
  }

  #evictToCap(maxRecords: number): void {
    while (this.#total > maxRecords || this.#bytes > this.#maxBytes) {
      const oldest = this.#order.shift();
      if (oldest === undefined) break;
      const bucket = this.#scopes.get(oldest.scope);
      if (bucket === undefined) continue;
      const at = bucket.findIndex((entry) => entry.seq === oldest.seq);
      // A missing seq means the entry was already evicted; Rust drops the stale
      // order slot without touching `total`, and so does this.
      if (at < 0) continue;
      const [removed] = bucket.splice(at, 1);
      this.#total -= 1;
      this.#bytes -= removed?.response.body.byteLength ?? 0;
      if (bucket.length === 0) this.#scopes.delete(oldest.scope);
    }
  }

  /** Drop everything. Tests only — Rust had no equivalent and needs none. */
  clear(): void {
    this.#scopes.clear();
    this.#order.length = 0;
    this.#seqCounter = 0;
    this.#total = 0;
    this.#bytes = 0;
  }
}

/**
 * The isolate's semantic cache — the closest reachable form of Rust's
 * process-global `AppState.semantic_cache`. See the module header for the
 * platform limit this stands in for.
 */
let shared: SemanticResponseCache | undefined;

export function sharedSemanticCache(): SemanticResponseCache {
  shared ??= new SemanticResponseCache();
  return shared;
}

/** Reset the isolate singleton. For tests that assert entry counts. */
export function resetSharedSemanticCache(): void {
  shared?.clear();
}
