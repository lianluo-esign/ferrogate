/**
 * `/sites/{site}/{path}` → what to serve, redirect to, or refuse (issue #737).
 *
 * Pure: no storage, no HTTP, no service. Everything a static host has to get
 * right about URLs and nothing else, so the rules can be asserted directly
 * instead of through five R2 fixtures.
 *
 * ## One document, one URL
 *
 * `/docs`, `/docs/` and `/docs/index.html` name the same document. A naive
 * proxy answers all three with the same body, which is three URLs to cache,
 * three URLs for a crawler to index, and two of them wrong the moment the
 * document contains a relative link (`<img src="logo.png">` under `/docs`
 * resolves to `/logo.png`, under `/docs/` to `/docs/logo.png`).
 *
 * The rule here is that the DIRECTORY URL is canonical and everything else
 * redirects to it, permanently:
 *
 * | request                | answer                                   |
 * |------------------------|------------------------------------------|
 * | `/sites/s`             | `308` → `/sites/s/`                      |
 * | `/sites/s/`            | the bytes of `index.html`                |
 * | `/sites/s/docs`        | `308` → `/sites/s/docs/` *if* that directory has an index; otherwise a miss |
 * | `/sites/s/docs/`       | the bytes of `docs/index.html`           |
 * | `/sites/s/docs/index.html` | `308` → `/sites/s/docs/`             |
 *
 * `308` rather than `301`: a `301` historically licenses a client to rewrite a
 * POST into a GET, and while nothing POSTs here today, the permanent-and-method-
 * preserving redirect is the one that means what this actually means.
 *
 * ## What is refused rather than resolved
 *
 * `..`, a backslash, a control character, and a percent-encoded separator —
 * `%2f`, `%5c` — are refused with `400`, not normalised. #736's expander
 * already refuses to WRITE such a path, so nothing in the index can be reached
 * by one; the refusal exists so that the two sides tell the same story and so
 * that a normalising proxy in front of the gateway cannot smuggle a different
 * path than the one the gateway authorised. A percent-encoded separator is
 * refused specifically because decoding it first would make `a%2f..%2fb` a
 * traversal that the pre-decode check never saw.
 */

export type SitePathPlan =
  /** `400` — the path is not a legal bundle path. */
  | { readonly kind: "invalid"; readonly reason: string }
  /** `308` — the canonical URL of the requested document. */
  | { readonly kind: "redirect"; readonly location: string }
  /** Look these up, in order, and serve the first that exists. */
  | {
      readonly kind: "resolve";
      readonly slug: string;
      /** The file the request names outright. */
      readonly file: string;
      /**
       * Only for a path with no trailing slash: if {@link file} is absent but
       * this one exists, the request named a DIRECTORY and must be redirected
       * to {@link SiteDirectoryProbe.location} rather than served — otherwise
       * the same document would exist at two URLs.
       */
      readonly directoryProbe: SiteDirectoryProbe | null;
      /** Whether the request URL was itself a directory URL. */
      readonly directory: boolean;
    };

export interface SiteDirectoryProbe {
  readonly file: string;
  readonly location: string;
}

/** The file a directory URL serves. Not configurable: one rule, everywhere. */
export const SITE_INDEX_DOCUMENT = "index.html";

/**
 * Control characters and the backslash, written as UNICODE ESCAPES.
 *
 * Escapes and not literal bytes: `test/source-nul-bytes.test.ts` bans a raw
 * NUL anywhere under any app's `src/`, and #736 is why — two literal NULs in a
 * test file made git classify it as BINARY, so the 684-line suite at the centre
 * of that PR produced no diff hunk and was invisible to review and to grep.
 *
 * Matching control characters IS the point — the same suppression, for the same
 * reason, as `src/assets/schemas.ts`'s `addressSegment`: a decoded segment
 * becomes an object-index key and a response header value, so a raw CR/LF must
 * be refused rather than smuggled into either.
 */
// biome-ignore lint/suspicious/noControlCharactersInRegex: see above
const ILLEGAL_DECODED = /[\u0000-\u001f\u007f\\]/;

/**
 * A percent-encoded separator, checked BEFORE decoding.
 *
 * `%2f` would otherwise become a path separator only after the segment split
 * had already happened, i.e. a segment that passed the `..` check as
 * `..%2f..` and became `../..` afterwards.
 */
const ENCODED_SEPARATOR = /%2f|%5c/i;

function decodeSegment(raw: string): string | null {
  try {
    return decodeURIComponent(raw);
  } catch {
    // A lone `%` or a truncated escape. Refused rather than passed through:
    // whatever the client meant, it is not a path this bundle can contain.
    return null;
  }
}

/**
 * Plan one request. `rest` is the raw (still percent-encoded) path after
 * `/sites/`; `search` is the query string including its `?`, carried onto every
 * redirect so a `?v=2` cache-buster survives the canonicalisation.
 */
export function planSitePath(rest: string, search = ""): SitePathPlan {
  if (ENCODED_SEPARATOR.test(rest)) {
    return { kind: "invalid", reason: "path contains a percent-encoded separator" };
  }
  const rawSegments = rest.split("/");
  const rawSlug = rawSegments[0] ?? "";
  const slug = decodeSegment(rawSlug);
  if (slug === null || slug === "" || ILLEGAL_DECODED.test(slug) || slug === "." || slug === "..") {
    return { kind: "invalid", reason: "the first path segment must name a site" };
  }
  return planWithin(slug, `/sites/${encodeURIComponent(slug)}`, rawSegments.slice(1), search);
}

/**
 * The same plan for a request that arrived on a VERIFIED CUSTOM DOMAIN (issue
 * #738), where the site occupies the WHOLE authority instead of a `/sites/{slug}`
 * subtree.
 *
 * Everything a static host has to get right about URLs — the trailing-slash
 * canonicalisation, the `index.html` collapse, the traversal and
 * percent-encoded-separator refusals — is {@link planWithin}, called with a
 * different base and with the slug supplied by the hostname rather than read
 * off the path. That is deliberate and it is the same rule the serve path
 * follows: a second copy of these rules is how `..` comes to be refused on one
 * URL space and normalised on the other.
 *
 * `path` is the raw (still percent-encoded) request path, INCLUDING its leading
 * `/`; the base is the empty string, so every redirect this produces is
 * authority-relative (`/docs/`) and never leaks the internal `/sites/{slug}`
 * spelling to a browser that asked for the custom domain.
 */
export function planSiteDomainPath(slug: string, path: string, search = ""): SitePathPlan {
  if (ENCODED_SEPARATOR.test(path)) {
    return { kind: "invalid", reason: "path contains a percent-encoded separator" };
  }
  // `"/"` splits to `["", ""]`; dropping the leading empty segment leaves
  // `[""]`, which {@link planWithin} reads as "the root directory URL" — the
  // same shape `/sites/{slug}/` produces. A path that somehow arrives without
  // its leading slash is treated identically rather than rejected, because the
  // only thing the leading slash carries here is that emptiness.
  const segments = path.startsWith("/") ? path.slice(1).split("/") : path.split("/");
  return planWithin(slug, "", segments, search);
}

/**
 * The shared core: which document a URL names inside ONE site, given the URL
 * prefix that site is mounted under.
 *
 * `base` is `"/sites/{slug}"` for the path route and `""` for a custom domain,
 * and it appears only in the redirect LOCATIONS — the resolved file path is a
 * bundle path and is identical either way, which is what makes the two entry
 * points resolve the same bytes through the same `AssetService`.
 */
function planWithin(
  slug: string,
  base: string,
  rawTail: readonly string[],
  search: string,
): SitePathPlan {
  // A trailing empty segment IS the trailing slash — `docs/a/` splits to
  // ["docs","a",""]. Drop it and remember it, because it is the difference
  // between "serve this file" and "serve this directory's index".
  const tail = [...rawTail];
  const directory = tail.length > 0 && tail[tail.length - 1] === "";
  if (directory) tail.pop();

  const decoded: string[] = [];
  for (const raw of tail) {
    const segment = decodeSegment(raw);
    if (segment === null) return { kind: "invalid", reason: "path is not valid percent-encoding" };
    if (segment === "") return { kind: "invalid", reason: "path contains an empty segment" };
    if (segment === "." || segment === "..") {
      return { kind: "invalid", reason: "path contains a relative segment" };
    }
    if (ILLEGAL_DECODED.test(segment)) {
      return { kind: "invalid", reason: "path contains an illegal character" };
    }
    decoded.push(segment);
  }

  const path = decoded.join("/");

  // `/sites/s` — the site root without its slash. One redirect, so the site's
  // own relative links resolve against the site and not against `/sites/`.
  // Unreachable from a custom domain, where the root is always `/`.
  if (path === "" && !directory) {
    return { kind: "redirect", location: `${base}/${search}` };
  }

  // An explicit `.../index.html` is the same document as `.../`, so it moves
  // there rather than becoming a second URL for the same bytes.
  if (!directory && decoded[decoded.length - 1] === SITE_INDEX_DOCUMENT) {
    const parent = decoded.slice(0, -1);
    const location = `${base}/${parent.map(encodeURIComponent).join("/")}${parent.length > 0 ? "/" : ""}${search}`;
    return { kind: "redirect", location };
  }

  if (directory) {
    return {
      kind: "resolve",
      slug,
      file: path === "" ? SITE_INDEX_DOCUMENT : `${path}/${SITE_INDEX_DOCUMENT}`,
      directoryProbe: null,
      directory: true,
    };
  }

  return {
    kind: "resolve",
    slug,
    file: path,
    directoryProbe: {
      file: `${path}/${SITE_INDEX_DOCUMENT}`,
      location: `${base}/${decoded.map(encodeURIComponent).join("/")}/${search}`,
    },
    directory: false,
  };
}
