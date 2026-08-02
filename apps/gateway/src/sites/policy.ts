/**
 * What a site response may be cached as, and by whom (issue #737).
 *
 * `GET /v1/assets/**` sends ONE `cache-control` for every byte it has ever
 * served — `private, max-age=0, must-revalidate` — which is right for an
 * artifact pulled by identity by a credential and wrong for a website. A site
 * is read by browsers and by CDNs, and the two halves of it have opposite
 * requirements:
 *
 *  - **A fingerprinted file** (`app.4f3a9c21.js`) is content-addressed by its
 *    NAME. Its bytes can never change without its URL changing, so it is
 *    `immutable` for a year and should never be revalidated at all.
 *  - **An HTML document** sits behind a MUTABLE pointer. `/sites/docs/` means
 *    "whatever the `latest` channel resolves to right now", and that changes
 *    the moment a new version is published. Caching it for even a minute means
 *    a deploy is not visible when the operator says it is.
 *
 * Getting the distinction wrong in either direction is a real failure: one
 * `max-age` for everything either serves a stale site until the TTL expires, or
 * throws away the only caching that matters (the fingerprinted bundle, which is
 * ~all of a modern site's bytes).
 *
 * ## `private` vs `public`
 *
 * Decided by whether the SITE is anonymously servable, not by whether THIS
 * reader presented a credential. The bytes of a public site are public no
 * matter who fetched them, and a private site's bytes must never be stored by a
 * shared cache even when the credential that fetched them was valid. Every
 * response also carries `vary`, because the same URL answers differently
 * depending on the credential.
 *
 * ## The Cache API is deliberately NOT used
 *
 * `caches.default` keys on the request URL. The correctness-relevant inputs
 * here are the URL *plus* the resolved version (a channel pointer moves) *plus*
 * the principal (a private site refuses an anonymous reader) — and a cache
 * whose key omits either of those serves one tenant's document to another, or
 * serves a version that has been superseded or YANKED. A key that included them
 * would have to resolve the channel and authenticate the caller before it could
 * be computed, which is the entire cost of the request bar the R2 read.
 *
 * So this slice caches with VALIDATORS instead: a strong `etag` on every
 * response, `304` on a match (handled by `evaluateConditionalRequest`, the same
 * code the asset pull uses), and the directives below for the browser and the
 * CDN in front of us. That is a decision, not an omission — an edge cache that
 * stores a yanked site indefinitely is a worse failure than an R2 read.
 */

/** One year, the ceiling RFC 8246 `immutable` is conventionally paired with. */
export const SITE_IMMUTABLE_MAX_AGE_SECONDS = 31_536_000;

/**
 * How long a NON-fingerprinted, non-HTML file may be reused without asking.
 *
 * Deliberately short and deliberately non-zero: `logo.png` under a mutable
 * channel can change without its name changing, so it cannot be `immutable`,
 * but making it revalidate on every request would mean a page with 30 images
 * costs 30 conditional round trips to save nothing.
 */
export const SITE_DEFAULT_MAX_AGE_SECONDS = 60;

/** The credential headers a site response varies on. */
export const SITE_VARY = "authorization, x-api-key";

/**
 * Does this filename carry a content fingerprint?
 *
 * The rule: the last `.`- or `-`-separated token before the extension is at
 * least 8 characters of `[A-Za-z0-9_-]`, AND it looks like a digest rather than
 * a word — it contains a digit, or it mixes upper and lower case. That admits
 * webpack/rollup hex (`app.4f3a9c21.js`), Vite's base64url
 * (`index-DiwrgTda.js`) and `main.a1b2c3d4e5f6.css`, and rejects
 * `jquery.min.js`, `styles.mobile.css` and `bootstrap-reboot.css`.
 *
 * It is deliberately CONSERVATIVE, because the two errors are not symmetric: a
 * missed fingerprint costs one conditional request per file, while a false
 * positive pins a mutable file in every browser cache in the world for a year
 * with no way to recall it. Anything the rule is unsure about gets the short
 * TTL.
 */
export function isFingerprintedFilename(path: string): boolean {
  const filename = path.slice(path.lastIndexOf("/") + 1);
  const match = /[.-]([A-Za-z0-9_-]{8,64})[.][A-Za-z0-9]+$/.exec(filename);
  const token = match?.[1];
  if (token === undefined) return false;
  const hasDigit = /[0-9]/.test(token);
  const mixedCase = /[a-z]/.test(token) && /[A-Z]/.test(token);
  return hasDigit || mixedCase;
}

/** A response's cacheability inputs. */
export interface SiteCachePolicyInput {
  /** Bundle-relative path actually served. */
  readonly path: string;
  /** Content type recorded for it at publish time. */
  readonly contentType: string;
  /** Whether the SITE may be served without a credential. */
  readonly publicSite: boolean;
  /**
   * Whether this response is a FALLBACK document — the SPA entry point or the
   * site's `404.html`. Those are served under a URL that is not their own, so
   * they must never be stored against it beyond the current response.
   */
  readonly fallback: boolean;
}

/** The `cache-control` header value for one site response. */
export function siteCacheControl(input: SiteCachePolicyInput): string {
  const scope = input.publicSite ? "public" : "private";
  if (input.fallback) {
    // A `404.html` served at `/missing` and an SPA shell served at `/orders/42`
    // are answers about a URL whose real content may appear at any moment.
    return `${scope}, no-store`;
  }
  const html = input.contentType.startsWith("text/html");
  if (!html && isFingerprintedFilename(input.path)) {
    return `${scope}, max-age=${SITE_IMMUTABLE_MAX_AGE_SECONDS}, immutable`;
  }
  if (html) {
    // The channel pointer is mutable and this document is what resolves it, so
    // it is revalidated every single time. The `etag` makes that cheap.
    return `${scope}, max-age=0, must-revalidate`;
  }
  return `${scope}, max-age=${SITE_DEFAULT_MAX_AGE_SECONDS}, must-revalidate`;
}
