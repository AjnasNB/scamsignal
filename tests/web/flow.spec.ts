import { test, expect, type Page } from "@playwright/test";
import { createHash } from "node:crypto";
import type { ScanReport } from "../../apps/web/src/types";

const fileBytes = Buffer.from("Harmless browser upload test fixture");
const report: ScanReport = {
  schema_version: 1,
  apk_sha256: createHash("sha256").update(fileBytes).digest("hex"),
  file_size: fileBytes.length,
  package_name: "dev.scamsignal.fixture",
  version_name: "1.0",
  version_code: 1,
  app_name: "Review fixture",
  signature: {
    status: "verified",
    signer_sha256: ["a".repeat(64)],
    schemes: ["v2"],
    errors: [],
  },
  permissions: [
    {
      name: "android.permission.READ_SMS",
      category: "sensitive",
      description_en: "Requests access to read SMS messages.",
      description_hi: "SMS संदेश पढ़ने की अनुमति माँगता है।",
    },
  ],
  findings: [
    {
      id: "sms",
      severity: "review",
      title_en: "SMS access requested",
      title_hi: "SMS की पहुँच माँगी गई",
      evidence: ["android.permission.READ_SMS"],
      explanation_en:
        "Check whether this permission fits the app’s purpose. Declared access does not prove use.",
      explanation_hi:
        "देखें कि यह अनुमति ऐप के काम के लिए उचित है या नहीं। घोषित पहुँच उपयोग का प्रमाण नहीं है।",
    },
  ],
  coverage: {
    manifest: true,
    signature: true,
    dex: false,
    notes: ["Static inspection does not execute the application."],
  },
  analyzed_at: "2026-10-11T12:00:00Z",
};

test("phone upload workspace stays usable and switches to Hindi", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(
    page.getByRole("button", { name: "Choose an APK", exact: true }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBeTruthy();
  await page.getByRole("button", { name: "Switch to Hindi" }).click();
  await expect(
    page.getByRole("button", { name: "APK चुनें", exact: true }),
  ).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("lang", "hi");
});

test("unsupported files show an actionable error without starting a scan", async ({
  page,
}) => {
  let uploads = 0;
  await page.route("**/api/scans", (route) => {
    uploads++;
    return route.abort();
  });
  await page.goto("/");
  await page.locator("input[type=file]").setInputFiles({
    name: "message.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("text"),
  });
  await expect(page.getByRole("alert")).toContainText(
    "Choose an Android .apk file",
  );
  expect(uploads).toBe(0);
});

test("upload report keeps signature evidence separate from unavailable public warnings", async ({
  page,
}) => {
  await page.route("**/api/scans", (route) =>
    route.fulfill({
      json: {
        scan_id: "fixture-scan",
        access_token: "private-test-token",
        status: "queued",
      },
    }),
  );
  await page.route("**/api/scans/fixture-scan", (route) => {
    expect(route.request().headers().authorization).toBe(
      "Bearer private-test-token",
    );
    return route.fulfill({ json: { status: "completed", report } });
  });
  await page.route("**/data/trust-policy.json", (route) =>
    route.fulfill({ json: { trusted_creators: [`0x${"1".repeat(40)}`] } }),
  );
  await page.route(/https:\/\/rpc\.tiramisu\./, (route) => route.abort());
  await page.goto("/");
  await page.locator("input[type=file]").setInputFiles({
    name: "fixture.apk",
    mimeType: "application/vnd.android.package-archive",
    buffer: fileBytes,
  });
  await expect(
    page.getByRole("heading", { name: "Review fixture", exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Live analysis", { exact: true })).toBeVisible();
  await expect(
    page.getByText("Verified", { exact: true }).first(),
  ).toBeVisible();
  await expect(
    page.getByText("Public evidence is unavailable right now"),
  ).toBeVisible();
  await expect(
    page.locator(".report-summary > div").filter({ hasText: "AppPassport" }),
  ).toContainText("Lookup unavailable");
  await page.getByRole("tab", { name: "Permissions (1)" }).click();
  await expect(page.getByRole("tabpanel")).toContainText("READ_SMS");
  await expect(page.getByRole("tabpanel")).toContainText(
    "does not mean a permission was granted or used",
  );
  await page.getByRole("button", { name: "Switch to Hindi" }).click();
  await expect(page.getByRole("tabpanel")).toContainText("SMS संदेश पढ़ने");
  await page.getByRole("button", { name: "Switch to English" }).click();
  await page.getByRole("tab", { name: "Identity & evidence" }).click();
  await expect(page.getByRole("tabpanel")).toContainText(
    "dev.scamsignal.fixture",
  );
  await expect(page.getByRole("tabpanel")).toContainText(
    "Release references could not be queried",
  );
  await expect(page.getByRole("tabpanel")).not.toContainText(
    "No accepted reference was found",
  );
  await expect(page.getByText("100% safe")).toHaveCount(0);
});

test("a server report for a different file is withheld", async ({ page }) => {
  await page.route("**/api/scans", (route) =>
    route.fulfill({
      json: { scan_id: "mismatch", access_token: "token", status: "queued" },
    }),
  );
  await page.route("**/api/scans/mismatch", (route) =>
    route.fulfill({
      json: {
        status: "completed",
        report: { ...report, apk_sha256: "b".repeat(64) },
      },
    }),
  );
  await page.goto("/");
  await page.locator("input[type=file]").setInputFiles({
    name: "fixture.apk",
    mimeType: "application/vnd.android.package-archive",
    buffer: fileBytes,
  });
  await expect(page.getByRole("alert")).toContainText(
    "does not match the uploaded file",
  );
  await expect(
    page.getByRole("heading", { name: "Review fixture", exact: true }),
  ).toHaveCount(0);
});

test("independent viewer validates hashes and never uploads an APK", async ({
  page,
}) => {
  let uploads = 0;
  await page.route("**/api/scans", (route) => {
    uploads++;
    return route.abort();
  });
  await page.goto("/viewer");
  await page.getByLabel("APK SHA-256", { exact: true }).fill("invalid");
  await page.getByRole("button", { name: "Find records", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("64-character");
  expect(uploads).toBe(0);
});

async function mockRecordClient(page: Page) {
  await page.route(/\/packages\/arkiv-client\/src\/index\.ts/, (route) =>
    route.fulfill({
      contentType: "application/javascript",
      body: `
      export async function resolveReport(report) {
        return {status:'available',passport:{status:report.signature.status==='verified'?'unknown':'incomplete',records:[]},warnings:[],ignored_count:0};
      }
      export async function listPublicRecords() {
        return {records:(window.__viewerFixtureRecords||[]).filter(record=>new Date(record.expires_at).getTime()>Date.now()),ignored_count:0};
      }
      export function resolveRecords(report,records) {
        return {status:'available',passport:{status:'incomplete',records:records.filter(record=>record.kind==='passport')},warnings:records.filter(record=>record.kind==='advisory'),ignored_count:0};
      }
      export function watchRecords(onChange,onError) {
        window.__notifyViewerRecords=onChange;window.__failViewerStream=onError;
        return ()=>{window.__notifyViewerRecords=undefined;window.__failViewerStream=undefined};
      }
    `,
    }),
  );
}

test("no reference and incomplete signature produce distinct identity states", async ({
  page,
}) => {
  await mockRecordClient(page);
  let signatureStatus: "verified" | "unavailable" = "verified";
  await page.route("**/api/scans", (route) =>
    route.fulfill({
      json: {
        scan_id: "identity-states",
        access_token: "token",
        status: "queued",
      },
    }),
  );
  await page.route("**/api/scans/identity-states", (route) =>
    route.fulfill({
      json: {
        status: "completed",
        report: {
          ...report,
          signature: { ...report.signature, status: signatureStatus },
        },
      },
    }),
  );
  await page.goto("/");
  await page
    .locator("input[type=file]")
    .setInputFiles({
      name: "fixture.apk",
      mimeType: "application/vnd.android.package-archive",
      buffer: fileBytes,
    });
  const identity = page
    .locator(".report-summary > div")
    .filter({ hasText: "AppPassport" });
  await expect(identity).toContainText("No exact release match");
  await expect(
    page.getByText("No matching active warning found"),
  ).toBeVisible();
  signatureStatus = "unavailable";
  await page
    .locator("input[type=file]")
    .setInputFiles({
      name: "fixture.apk",
      mimeType: "application/vnd.android.package-archive",
      buffer: fileBytes,
    });
  await expect(identity).toContainText("Comparison incomplete");
  await expect(identity).not.toContainText("No exact release match");
});

test("independent viewer refreshes expired warnings and responds to live updates", async ({
  page,
}) => {
  await mockRecordClient(page);
  await page.clock.install({ time: new Date("2026-10-11T12:00:00Z") });
  await page.clock.pauseAt(new Date("2026-10-11T12:00:00Z"));
  await page.addInitScript(() => {
    (
      window as unknown as { __viewerFixtureRecords: unknown[] }
    ).__viewerFixtureRecords = [
      {
        kind: "advisory",
        key: "0x" + "b".repeat(64),
        creator: "0x" + "1".repeat(40),
        package_name: "dev.scamsignal.fixture",
        title: "Temporary reviewed warning",
        summary: "Controlled expiry fixture.",
        expires_at: new Date(Date.now() + 60000).toISOString(),
      },
    ];
  });
  await page.goto("/viewer");
  await page.getByLabel("APK SHA-256", { exact: true }).fill(report.apk_sha256);
  await page.getByRole("button", { name: "Find records", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Temporary reviewed warning" }),
  ).toBeVisible();
  await expect(
    page.getByText("refreshes every 60 seconds", { exact: false }),
  ).toBeVisible();
  await page.clock.runFor(61000);
  await expect(
    page.getByRole("heading", { name: "Temporary reviewed warning" }),
  ).toHaveCount(0);
  await expect(
    page.getByText("No matching active warning found"),
  ).toBeVisible();
  await page.evaluate(() => {
    const fixture = window as unknown as {
      __viewerFixtureRecords: unknown[];
      __notifyViewerRecords: () => void;
      __failViewerStream: (e: Error) => void;
    };
    fixture.__viewerFixtureRecords = [
      {
        kind: "advisory",
        key: "0x" + "c".repeat(64),
        creator: "0x" + "1".repeat(40),
        package_name: "dev.scamsignal.fixture",
        title: "New reviewer warning",
        summary: "Controlled live update fixture.",
        expires_at: new Date(Date.now() + 60000).toISOString(),
      },
    ];
    fixture.__notifyViewerRecords();
  });
  await page.clock.runFor(500);
  await expect(
    page.getByRole("heading", { name: "New reviewer warning" }),
  ).toBeVisible();
  await page.evaluate(() => {
    const fixture = window as unknown as {
      __viewerFixtureRecords: unknown[];
      __notifyViewerRecords: () => void;
      __failViewerStream: (e: Error) => void;
    };
    fixture.__viewerFixtureRecords = [];
    fixture.__notifyViewerRecords();
    fixture.__failViewerStream(new Error("Test disconnect"));
  });
  await page.clock.runFor(500);
  await expect(
    page.getByRole("heading", { name: "New reviewer warning" }),
  ).toHaveCount(0);
  await expect(
    page.getByText("Live updates are interrupted.", { exact: false }),
  ).toBeVisible();
});
