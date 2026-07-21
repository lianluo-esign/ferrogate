import AxeBuilder from "@axe-core/playwright";
import {
  expect,
  test as base,
  type Locator,
  type Page,
  type TestInfo,
} from "@playwright/test";

type AxeImpact = "minor" | "moderate" | "serious" | "critical";

function browserContext(page: Page, testInfo: TestInfo): string {
  const viewport = page.viewportSize();
  return [
    `route=${new URL(page.url()).pathname}`,
    `viewport=${viewport ? `${viewport.width}x${viewport.height}` : "unknown"}`,
    `project=${testInfo.project.name}`,
  ].join(" ");
}

export const test = base.extend({
  page: async ({ page }, runTest, testInfo) => {
    const consoleErrors: string[] = [];
    const pageErrors: string[] = [];

    page.on("console", (message) => {
      if (message.type() === "error") consoleErrors.push(message.text());
    });
    page.on("pageerror", (error) => pageErrors.push(error.message));

    await runTest(page);

    const context = browserContext(page, testInfo);
    expect.soft(pageErrors, `Uncaught page errors (${context})`).toEqual([]);
    expect.soft(consoleErrors, `Browser console errors (${context})`).toEqual([]);
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

export async function expectNoAxeViolations(
  page: Page,
  testInfo: TestInfo,
  failImpacts: AxeImpact[],
): Promise<void> {
  const result = await new AxeBuilder({ page }).analyze();
  await testInfo.attach("axe-report", {
    body: Buffer.from(JSON.stringify(result, null, 2)),
    contentType: "application/json",
  });

  const violations = result.violations.filter(
    (violation) =>
      violation.impact !== null && failImpacts.includes(violation.impact as AxeImpact),
  );
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
