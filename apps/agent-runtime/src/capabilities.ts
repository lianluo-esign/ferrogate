/**
 * Capability-string normalization, on its own so both the in-memory registry
 * (`ports.ts`) and the durable one (`durable/adapters.ts`) can share ONE
 * implementation without an import cycle between them.
 *
 * A leaf module: it imports nothing. `ports.ts` re-exports
 * {@link normalizedCapabilities} so every existing importer is unaffected.
 */

/** Rust `normalized_capabilities`: trimmed, lowercased, deduped, sorted. */
export function normalizedCapabilities(
  capabilities: readonly string[] | undefined,
): readonly string[] {
  const seen = new Set<string>();
  for (const raw of capabilities ?? []) {
    const value = raw.trim().toLowerCase();
    if (value !== "") seen.add(value);
  }
  return [...seen].sort();
}
