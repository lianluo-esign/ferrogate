/**
 * Port of `ferrogate-config`'s `config/snapshot.rs` (inventory §5.4, "Snapshot
 * id"): a stable, change-detecting id for a serialized config.
 *
 * `config_snapshot_id` = FNV-1a-64 hex of the serialized JSON config. The Rust
 * source hashes `serde_json::to_vec(config)`; this hashes the UTF-8 bytes of
 * `JSON.stringify(config)`. The exact bytes differ from Rust (a clean-room
 * re-implementation is not byte-compatible across languages), but the two
 * invariants the callers rely on hold: it is stable for equal input and
 * changes when the config changes.
 */

const FNV_OFFSET_BASIS = 0xcbf29ce484222325n;
const FNV_PRIME = 0x00000100000001b3n;
const U64_MASK = (1n << 64n) - 1n;

/** FNV-1a-64 over raw bytes, returned as an unsigned 64-bit BigInt. */
export function fnv1a64(bytes: Uint8Array): bigint {
  let hash = FNV_OFFSET_BASIS;
  for (const byte of bytes) {
    hash ^= BigInt(byte);
    hash = (hash * FNV_PRIME) & U64_MASK;
  }
  return hash;
}

/** Stable 16-hex-char id of a config value (FNV-1a-64 of its JSON bytes). */
export function configSnapshotId(config: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(config));
  return fnv1a64(bytes).toString(16).padStart(16, "0");
}
