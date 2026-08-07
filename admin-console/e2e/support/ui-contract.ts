import AxeBuilder from "@axe-core/playwright";
import {
  expect,
  test as base,
  type Locator,
  type Page,
  type TestInfo,
} from "@playwright/test";

type AxeImpact = "minor" | "moderate" | "serious" | "critical";
interface UiContractOptions {
  expectedConsoleErrors: RegExp[];
  expectedPageErrors: RegExp[];
}

function browserContext(page: Page, testInfo: TestInfo): string {
  const viewport = page.viewportSize();
  return [
    `route=${new URL(page.url()).pathname}`,
    `viewport=${viewport ? `${viewport.width}x${viewport.height}` : "unknown"}`,
    `project=${testInfo.project.name}`,
  ].join(" ");
}

/** See the normalization note in the `page` fixture below. */
function normalizePatterns(value: unknown): RegExp[] {
  if (value instanceof RegExp) return [value];
  if (Array.isArray(value)) {
    return value.flat(Infinity).filter((entry): entry is RegExp => entry instanceof RegExp);
  }
  return [];
}

export const test = base.extend<UiContractOptions>({
  expectedConsoleErrors: [[], { option: true }],
  expectedPageErrors: [[], { option: true }],
  page: async ({ page, expectedConsoleErrors, expectedPageErrors }, runTest, testInfo) => {
    const consoleErrors: string[] = [];
    const pageErrors: string[] = [];

    page.on("console", (message) => {
      if (message.type() === "error") consoleErrors.push(message.text());
    });
    page.on("pageerror", (error) => pageErrors.push(error.message));

    await runTest(page);

    const context = browserContext(page, testInfo);
    // NORMALIZED, not trusted as `RegExp[]`: Playwright parses an ARRAY value
    // in `test.use({ option: [a, b] })` as a `[value, config]` fixture TUPLE,
    // so a spec writing the natural `expectedConsoleErrors: [/x/, /y/]`
    // delivers only `/x/` here (verified empirically on this repo's
    // Playwright). The failure mode was vicious: `.some` only runs when the
    // page actually LOGGED an error, so the harness crashed with
    // "expectedConsoleErrors.some is not a function" precisely on the tests
    // that had something to report. Accepting a lone RegExp or a nested array
    // keeps every spec's natural spelling working under either parse.
    const expectedConsole = normalizePatterns(expectedConsoleErrors);
    const expectedPage = normalizePatterns(expectedPageErrors);
    const unexpectedConsoleErrors = consoleErrors.filter(
      (message) => !expectedConsole.some((pattern) => pattern.test(message)),
    );
    const unexpectedPageErrors = pageErrors.filter(
      (message) => !expectedPage.some((pattern) => pattern.test(message)),
    );
    expect.soft(unexpectedPageErrors, `Uncaught page errors (${context})`).toEqual([]);
    expect.soft(unexpectedConsoleErrors, `Browser console errors (${context})`).toEqual([]);
  },
});

export { expect };

export async function expectNoDocumentOverflow(
  page: Page,
  testInfo: TestInfo,
): Promise<void> {
  const dimensions = await page.evaluate(() => ({
    bodyClientWidth: document.body.clientWidth,
    bodyScrollWidth: document.body.scrollWidth,
    documentClientWidth: document.documentElement.clientWidth,
    documentScrollWidth: document.documentElement.scrollWidth,
  }));

  const overflow = Math.max(
    dimensions.bodyScrollWidth - dimensions.bodyClientWidth,
    dimensions.documentScrollWidth - dimensions.documentClientWidth,
  );
  expect(
    overflow,
    `Horizontal document overflow (${browserContext(page, testInfo)}): ${JSON.stringify(dimensions)}`,
  ).toBeLessThanOrEqual(1);
}

/**
 * Wait for the page's FINITE animations/transitions to finish (a Radix dialog
 * fading out, a toast mid-fade). Infinite animations (spinners) are skipped,
 * and a hard 2s cap keeps a stuck transition from hanging the test.
 */
async function settleTransientAnimations(page: Page): Promise<void> {
  await page.evaluate(async () => {
    const finite = document.getAnimations().filter((animation) => {
      const timing = animation.effect?.getTiming();
      return Boolean(timing) && timing?.iterations !== Infinity;
    });
    await Promise.race([
      Promise.all(finite.map((animation) => animation.finished.catch(() => undefined))),
      new Promise((resolve) => setTimeout(resolve, 2_000)),
    ]);
  });
}

export async function expectNoAxeViolations(
  page: Page,
  testInfo: TestInfo,
  failImpacts: AxeImpact[],
): Promise<void> {
  const failing = (scan: Awaited<ReturnType<AxeBuilder["analyze"]>>) =>
    scan.violations.filter(
      (violation) =>
        violation.impact !== null && failImpacts.includes(violation.impact as AxeImpact),
    );

  let result = await new AxeBuilder({ page }).analyze();
  let violations = failing(result);
  if (violations.length > 0) {
    // Mid-animation states produce FALSE contrast failures: an element fading
    // in/out blends its foreground into the backdrop (e.g. a dismissing dialog
    // or an expiring toast at 50% opacity). Re-scan once on the settled UI —
    // a real violation persists and still fails below.
    await settleTransientAnimations(page);
    result = await new AxeBuilder({ page }).analyze();
    violations = failing(result);
  }
  await testInfo.attach("axe-report", {
    body: Buffer.from(JSON.stringify(result, null, 2)),
    contentType: "application/json",
  });

  const details = violations
    .flatMap((violation) =>
      violation.nodes.map(
        (node) =>
          `${violation.id} [${violation.impact}] ${node.target.join(" ")} - ${node.failureSummary ?? violation.help}`,
      ),
    )
    .join("\n");

  expect(
    violations,
    `axe violations (${browserContext(page, testInfo)})\n${details}`,
  ).toEqual([]);
}

export async function expectKeyboardFocus(
  page: Page,
  target: Locator,
  testInfo: TestInfo,
): Promise<void> {
  await page.evaluate(() => {
    if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
  });
  await page.keyboard.press("Tab");
  await expect(
    target,
    `Unexpected first keyboard target (${browserContext(page, testInfo)})`,
  ).toBeFocused();
}

export async function attachViewportScreenshot(
  page: Page,
  testInfo: TestInfo,
  name: string,
): Promise<void> {
  await testInfo.attach(`${name}-${testInfo.project.name}`, {
    body: await page.screenshot({ animations: "disabled" }),
    contentType: "image/png",
  });
}
