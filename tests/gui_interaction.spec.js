const { test, expect } = require("@playwright/test");

const baseURL = process.env.QCRYPTO_GUI_URL || "http://127.0.0.1:8765";

test("dashboard tools run without console errors", async ({ page }) => {
  const consoleErrors = [];
  page.on("console", (message) => {
    if (message.type() === "error") {
      consoleErrors.push(message.text());
    }
  });

  await page.goto(baseURL, { waitUntil: "networkidle" });
  await expect(page.getByText("Security Operations Console")).toBeVisible();
  await expect(page.getByText("Security posture")).toBeVisible();

  await page.locator('.nav button[data-panel="qch"]').click();
  await expect(page.locator('form[data-panel-id="qch"]')).toBeVisible();
  await page.locator('form[data-panel-id="qch"] button.run').click();
  await expect(page.locator("#result")).toContainText("pqc_profile");

  await page.locator('.nav button[data-panel="dlhp"]').click();
  await expect(page.locator('form[data-panel-id="dlhp"]')).toBeVisible();
  await page.locator('button[data-run-endpoint="/api/dlhp-chaff"]').click();
  await expect(page.locator("#result")).toContainText("chaff");

  await page.locator('.nav button[data-panel="catalog"]').click();
  await expect(page.locator('form[data-panel-id="catalog"]')).toBeVisible();
  await page.getByRole("button", { name: "List Algorithms" }).click();
  await expect(page.locator("#result")).toContainText("algorithms");

  await page.locator('.nav button[data-panel="sweep"]').click();
  await expect(page.locator('form[data-panel-id="sweep"]')).toBeVisible();
  await page.getByRole("button", { name: "Run Sweep" }).click();
  await expect(page.locator("#result")).toContainText("point_count");

  await page.locator('.nav button[data-panel="report"]').click();
  await expect(page.locator('form[data-panel-id="report"]')).toBeVisible();
  await page.getByRole("button", { name: "Build Report" }).click();
  await expect(page.locator("#result")).toContainText("production_ready");

  expect(consoleErrors).toEqual([]);
});

test("mobile layout has no horizontal page overflow", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(baseURL, { waitUntil: "networkidle" });
  await expect(page.getByText("Security Operations Console")).toBeVisible();

  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});
