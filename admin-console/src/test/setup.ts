// Global Vitest setup (wired via vite.config.ts `test.setupFiles`).
//
// Responsibilities:
//   1. jest-dom matchers (`toBeInTheDocument`, ...) on Vitest's `expect`.
//   2. MSW lifecycle: every test runs against the shared `server` from
//      `src/test/msw.ts`; unhandled requests are an error so a test can
//      never silently hit a real backend.
//   3. jsdom polyfills required by Radix UI primitives (pointer capture,
//      scrollIntoView, ResizeObserver, matchMedia).
import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterAll, afterEach, beforeAll } from "vitest";
import { LOCALES, loadCatalog } from "@/i18n";
import { server } from "@/test/msw";

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));

// Warm the lazy locale-chunk cache once per test file so `I18nProvider` renders
// EVERY locale SYNCHRONOUSLY under jsdom (production still lazy-loads the
// non-default catalogs via dynamic `import()` — see src/i18n/catalog.ts #393).
// This keeps the many `renderWithProviders(..., { locale: "zh-CN" })` page tests
// synchronous, so they need no `await` for the first assertion.
beforeAll(async () => {
  await Promise.all(LOCALES.map((locale) => loadCatalog(locale)));
});

afterEach(() => {
  server.resetHandlers();
  cleanup();
  window.localStorage.clear();
});

afterAll(() => server.close());

// --- jsdom polyfills for Radix UI (DropdownMenu / Select / Sheet) ---

if (!Element.prototype.hasPointerCapture) {
  Element.prototype.hasPointerCapture = () => false;
}
if (!Element.prototype.setPointerCapture) {
  Element.prototype.setPointerCapture = () => {};
}
if (!Element.prototype.releasePointerCapture) {
  Element.prototype.releasePointerCapture = () => {};
}
if (!Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = () => {};
}

if (!("ResizeObserver" in globalThis)) {
  class ResizeObserverStub {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  Object.defineProperty(globalThis, "ResizeObserver", {
    value: ResizeObserverStub,
    configurable: true,
  });
}

// jsdom (v26) ships Blob/File without the standard async `arrayBuffer()`, which
// the presigned large-object upload (#344) relies on to hash bytes client-side
// before requesting an intent. Browsers implement it natively; polyfill it here
// via jsdom's working FileReader so the flow is testable under jsdom.
if (typeof Blob !== "undefined" && !Blob.prototype.arrayBuffer) {
  Blob.prototype.arrayBuffer = function arrayBuffer(this: Blob) {
    return new Promise<ArrayBuffer>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as ArrayBuffer);
      reader.onerror = () => reject(reader.error);
      reader.readAsArrayBuffer(this);
    });
  };
}

if (!window.matchMedia) {
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    value: (query: string): MediaQueryList =>
      ({
        matches: false,
        media: query,
        onchange: null,
        addListener: () => {},
        removeListener: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: () => false,
      }) as unknown as MediaQueryList,
  });
}
