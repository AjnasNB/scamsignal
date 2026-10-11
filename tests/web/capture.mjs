import { chromium } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const output = new URL("./artifacts/", import.meta.url);
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({
  viewport: { width: 1440, height: 1080 },
  reducedMotion: "reduce",
});
await page.goto(process.env.WEB_TEST_URL || "http://localhost:5173/", {
  waitUntil: "networkidle",
});
await page.screenshot({
  path: fileURLToPath(new URL("home-desktop.png", output)),
  fullPage: true,
});
await page.setViewportSize({ width: 390, height: 844 });
await page.screenshot({
  path: fileURLToPath(new URL("home-mobile.png", output)),
  fullPage: true,
});
await page.getByRole("button", { name: "Switch to Hindi" }).click();
await page.screenshot({
  path: fileURLToPath(new URL("home-hindi.png", output)),
  fullPage: true,
});
console.log(
  JSON.stringify({
    desktop: "tests/web/artifacts/home-desktop.png",
    mobile: "tests/web/artifacts/home-mobile.png",
    hindi: "tests/web/artifacts/home-hindi.png",
    mobileOverflow: await page.evaluate(
      () => document.documentElement.scrollWidth > innerWidth,
    ),
  }),
);
await browser.close();
