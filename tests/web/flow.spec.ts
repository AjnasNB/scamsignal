import { test, expect, type Page } from "@playwright/test";
import { createHash } from "node:crypto";
import type { ScanReport } from "../../apps/web/src/types";
import {
  buildEntityInput,
  type PublishInput,
} from "../../packages/arkiv-client/src/index";

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
    "Artifact references could not be queried",
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
        window.__reportReadCount=(window.__reportReadCount||0)+1;
        if(window.__reportReadDelay) await new Promise(resolve=>setTimeout(resolve,window.__reportReadDelay));
        const active=record=>!record.expires_at||new Date(record.expires_at).getTime()>Date.now();
        const references=(window.__reportFixturePassports||[]).filter(active);
        return {status:'available',passport:{status:window.__fixturePassportStatus||(report.signature.status==='verified'?(references.length?'exact_match':'unknown'):'incomplete'),records:references},warnings:(window.__reportFixtureWarnings||[]).filter(active),ignored_count:0};
      }
      export async function listPublicRecords() {
        window.__viewerReadCount=(window.__viewerReadCount||0)+1;
        if (window.__stallViewerRead) return new Promise(()=>{});
        return {records:(window.__viewerFixtureRecords||[]).filter(record=>new Date(record.expires_at).getTime()>Date.now()),ignored_count:0};
      }
      export function resolveRecords(report,records) {
        return {status:'available',passport:{status:'incomplete',records:records.filter(record=>record.kind==='passport')},warnings:records.filter(record=>record.kind==='advisory'),ignored_count:0};
      }
      export function watchRecords(onChange,onError) {
        window.__notifyViewerRecords=onChange;window.__failViewerStream=onError;
        return ()=>{window.__notifyViewerRecords=undefined;window.__failViewerStream=undefined};
      }
      export async function connectReviewer(){return '0x'+'1'.repeat(40);}
      export async function publishRecord(input){window.__publishedFixture=input;return {entityKey:'0x'+'d'.repeat(64),txHash:'0x'+'e'.repeat(64)};}
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
  await page.locator("input[type=file]").setInputFiles({
    name: "fixture.apk",
    mimeType: "application/vnd.android.package-archive",
    buffer: fileBytes,
  });
  const identity = page
    .locator(".report-summary > div")
    .filter({ hasText: "AppPassport" });
  await expect(identity).toContainText("No exact reference match");
  await expect(
    page.getByText("No matching active warning found"),
  ).toBeVisible();
  signatureStatus = "unavailable";
  await page.locator("input[type=file]").setInputFiles({
    name: "fixture.apk",
    mimeType: "application/vnd.android.package-archive",
    buffer: fileBytes,
  });
  await expect(identity).toContainText("Comparison incomplete");
  await expect(identity).not.toContainText("No exact reference match");
});

test("a main report revalidates expiring references before the periodic refresh", async ({
  page,
}) => {
  await mockRecordClient(page);
  await page.clock.install({ time: new Date("2026-10-11T12:00:00Z") });
  await page.clock.pauseAt(new Date("2026-10-11T12:00:00Z"));
  await page.addInitScript(() => {
    const fixture = window as unknown as {
      __reportFixturePassports: unknown[];
      __reportFixtureWarnings: unknown[];
    };
    const shared = {
      creator: "0x" + "1".repeat(40),
      package_name: "dev.scamsignal.fixture",
      expires_at: new Date(Date.now() + 10000).toISOString(),
    };
    fixture.__reportFixturePassports = [
      {
        ...shared,
        kind: "passport",
        key: "0x" + "a".repeat(64),
        title: "Temporary artifact reference",
        summary: "Controlled short-lived reference.",
      },
    ];
    fixture.__reportFixtureWarnings = [
      {
        ...shared,
        kind: "advisory",
        key: "0x" + "b".repeat(64),
        title: "Temporary main-report warning",
        summary: "Controlled short-lived warning.",
      },
    ];
  });
  await page.route("**/api/scans", (route) =>
    route.fulfill({
      json: {
        scan_id: "expiry-report",
        access_token: "token",
        status: "queued",
      },
    }),
  );
  await page.route("**/api/scans/expiry-report", (route) =>
    route.fulfill({ json: { status: "completed", report } }),
  );
  await page.goto("/");
  await page.locator("input[type=file]").setInputFiles({
    name: "fixture.apk",
    mimeType: "application/vnd.android.package-archive",
    buffer: fileBytes,
  });
  const summary = page.locator("#report .report-summary");
  await expect(summary).toContainText("Exact reference match");
  await expect(summary).toContainText("1 active");
  await expect(
    page.getByRole("heading", { name: "Temporary main-report warning" }),
  ).toBeVisible();
  await page.evaluate(() => {
    (window as unknown as { __reportReadDelay: number }).__reportReadDelay =
      5000;
  });
  await page.clock.runFor(10002);
  await expect(summary).toContainText("Checking");
  await expect(summary).not.toContainText("Exact reference match");
  await expect(summary).not.toContainText("1 active");
  await expect(
    page.getByRole("heading", { name: "Temporary main-report warning" }),
  ).toHaveCount(0);
  expect(
    await page.evaluate(
      () =>
        (window as unknown as { __reportReadCount: number }).__reportReadCount,
    ),
  ).toBe(2);
  await page.clock.runFor(5001);
  await expect(summary).toContainText("No exact reference match");
  await expect(
    page.getByText("No matching active warning found"),
  ).toBeVisible();
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
  await page.clock.runFor(15000);
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
  await page.clock.runFor(15000);
  await expect(
    page.getByRole("heading", { name: "New reviewer warning" }),
  ).toHaveCount(0);
  await expect(
    page.getByText("Live updates are interrupted.", { exact: false }),
  ).toBeVisible();
});

test("a stalled public query ends with an unavailable state and allows retry", async ({
  page,
}) => {
  await mockRecordClient(page);
  await page.clock.install({ time: new Date("2026-10-11T12:00:00Z") });
  await page.clock.pauseAt(new Date("2026-10-11T12:00:00Z"));
  await page.addInitScript(() => {
    (window as unknown as { __stallViewerRead: boolean }).__stallViewerRead =
      true;
  });
  await page.goto("/viewer");
  await page.getByLabel("APK SHA-256", { exact: true }).fill(report.apk_sha256);
  await page.getByRole("button", { name: "Find records", exact: true }).click();
  await expect(
    page.getByText("Verifying current records…", { exact: true }),
  ).toBeVisible();
  await page.clock.runFor(30001);
  await expect(
    page.getByText("Public evidence is unavailable right now"),
  ).toBeVisible();
  await expect(page.getByText("No matching active warning found")).toHaveCount(
    0,
  );
  await expect(
    page.getByRole("button", { name: "Find records", exact: true }),
  ).toBeEnabled();
  await page.evaluate(() => {
    (window as unknown as { __stallViewerRead: boolean }).__stallViewerRead =
      false;
  });
  await page
    .getByRole("button", { name: "Refresh records", exact: true })
    .click();
  await expect(
    page.getByText("No matching active warning found"),
  ).toBeVisible();
});

test("bursts of record events respect the viewer refresh cooldown", async ({
  page,
}) => {
  await mockRecordClient(page);
  await page.clock.install({ time: new Date("2026-10-11T12:00:00Z") });
  await page.clock.pauseAt(new Date("2026-10-11T12:00:00Z"));
  await page.goto("/viewer");
  await page.getByLabel("APK SHA-256", { exact: true }).fill(report.apk_sha256);
  await page.getByRole("button", { name: "Find records", exact: true }).click();
  await expect(
    page.getByText("No matching active warning found"),
  ).toBeVisible();
  for (let index = 0; index < 5; index++) {
    await page.evaluate(() => {
      (
        window as unknown as { __notifyViewerRecords: () => void }
      ).__notifyViewerRecords();
    });
    await page.clock.runFor(2000);
  }
  expect(
    await page.evaluate(
      () =>
        (window as unknown as { __viewerReadCount: number }).__viewerReadCount,
    ),
  ).toBe(1);
  await page.clock.runFor(5001);
  expect(
    await page.evaluate(
      () =>
        (window as unknown as { __viewerReadCount: number }).__viewerReadCount,
    ),
  ).toBe(2);
});

test("the evaluation matrix preserves source classifications and remains usable in Hindi", async ({
  page,
}) => {
  await mockRecordClient(page);
  const samples = Array.from({ length: 12 }, (_, index) => ({
    id: `matrix-${index}`,
    name: `Controlled app ${index + 1}`,
    classification:
      index < 5
        ? "upstream-open-source-release"
        : index < 10
          ? "documented-malware-sample"
          : "intentionally-insecure-training-app",
    source_url: "https://example.org/research",
    evidence_confidence:
      index >= 5 && index < 10 ? "research-collection-label" : undefined,
    ground_truth_note:
      "Controlled provenance text; not an actual APK evaluation.",
    report: { ...report, app_name: `Controlled app ${index + 1}` },
  }));
  await page.route("**/data/evaluation.json", (route) =>
    route.fulfill({ json: { samples } }),
  );
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  const collection = page.locator(".evaluation-section");
  await expect(collection.locator("tbody tr")).toHaveCount(12);
  await expect(
    collection.getByText(
      "5 documented malware sample(s) in this collection have verified signatures.",
      { exact: false },
    ),
  ).toBeVisible();
  await collection.getByRole("button", { name: "Documented threats" }).click();
  await expect(collection.locator("tbody tr")).toHaveCount(5);
  await expect(collection.locator("tbody tr").first()).toContainText(
    "Documented malware",
  );
  await collection
    .locator("tbody tr")
    .first()
    .getByText("Source & context", { exact: true })
    .click();
  await expect(collection.locator("tbody tr").first()).toContainText(
    "independent primary-report attribution has not been established",
  );
  await expect(
    collection.getByRole("link", { name: "Source reference" }),
  ).toHaveAttribute("href", "https://example.org/research");
  await collection.getByRole("button", { name: "Training controls" }).click();
  await expect(collection.locator("tbody tr")).toHaveCount(2);
  await expect(collection.locator("tbody tr").first()).toContainText(
    "Training control",
  );
  await collection
    .getByRole("button", { name: "Check Arkiv evidence", exact: true })
    .click();
  await expect(
    collection.getByText("Arkiv snapshot checked", { exact: false }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Switch to Hindi" }).click();
  await expect(collection.locator("tbody tr").first()).toContainText(
    "प्रशिक्षण नमूना",
  );
  for (const width of [360, 390, 768]) {
    await page.setViewportSize({ width, height: 844 });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBeTruthy();
  }
  await page
    .getByRole("button", {
      name: "पढ़ें Controlled app 11 रिपोर्ट",
      exact: true,
    })
    .click();
  await expect(
    page.getByText("पूर्वनिर्मित डेमो", { exact: true }),
  ).toBeVisible();
});

test("a documented phishing sample keeps reviewer context visible with zero sensitive permissions", async ({
  page,
}) => {
  await mockRecordClient(page);
  await page.addInitScript(() => {
    const fixture = window as unknown as {
      __fixturePassportStatus: string;
      __reportFixtureWarnings: unknown[];
    };
    fixture.__fixturePassportStatus = "exact_match";
    fixture.__reportFixtureWarnings = [
      {
        key: "0x" + "c".repeat(64),
        creator: "0x" + "1".repeat(40),
        title: "Controlled phishing review",
        summary: "Controlled reviewer evidence fixture.",
        expires_at: "2026-10-25T12:00:00Z",
      },
    ];
  });
  await page.route("**/data/evaluation.json", (route) =>
    route.fulfill({
      json: {
        samples: [
          {
            id: "faketurk",
            name: "Controlled fake BtcTurk",
            classification: "documented-malware-sample",
            source_url: "https://example.org/primary-research",
            evidence_urls: ["https://example.org/primary-research"],
            evidence_confidence: "primary-report-hash-match",
            evidence_hash: { algorithm: "md5", value: "e".repeat(32) },
            ground_truth_note:
              "Controlled source context; this is not an actual malware report.",
            report: {
              ...report,
              package_name: "com.app.elipticsoft.app",
              permissions: [],
              findings: [
                {
                  id: "target-sdk",
                  severity: "review",
                  title_en: "Older Android protections targeted",
                  title_hi: "पुरानी एंड्रॉयड सुरक्षा लक्षित है",
                  evidence: ["targetSdkVersion = 27"],
                  explanation_en:
                    "An older target SDK can retain legacy platform behavior. This is a compatibility indicator, not proof of harmful activity.",
                  explanation_hi:
                    "पुराने टारगेट SDK से पुराना प्लेटफॉर्म व्यवहार बना रह सकता है। यह संगतता संकेत है, हानिकारक गतिविधि का प्रमाण नहीं।",
                },
              ],
            },
          },
        ],
      },
    }),
  );
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(
    page.getByText("A documented fake BtcTurk APK has a valid signature", {
      exact: false,
    }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Read this case", exact: true })
    .click();
  await expect(page.locator("#report")).toContainText(
    "Known research sample: documented malware",
  );
  await expect(page.locator("#report")).toContainText("0 declared");
  await expect(page.locator("#report")).toContainText("Exact reference match");
  await expect(page.locator("#report")).toContainText("1 active");
  await expect(
    page.getByRole("heading", {
      name: "Controlled phishing review",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByText("Precomputed demo", { exact: true }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBeTruthy();
  for (const language of ["en", "hi"]) {
    if (language === "hi")
      await page.getByRole("button", { name: "Switch to Hindi" }).click();
    const findingLayout = await page
      .locator("#report .finding")
      .evaluate((finding) => {
        const bounds = finding.getBoundingClientRect();
        const elements = [...finding.querySelectorAll("h4,p,.status-tag")];
        const textRects = elements.flatMap((element) => {
          const range = document.createRange();
          range.selectNodeContents(element);
          return [...range.getClientRects()].map((rect) => ({
            left: rect.left,
            right: rect.right,
          }));
        });
        const paragraph = finding.querySelector("p")!;
        const range = document.createRange();
        range.selectNodeContents(paragraph);
        return {
          allTextInside: textRects.every(
            (rect) =>
              rect.left >= bounds.left - 1 && rect.right <= bounds.right + 1,
          ),
          wrappedLines: range.getClientRects().length,
          paragraphWidth: paragraph.clientWidth,
          paragraphScrollWidth: paragraph.scrollWidth,
          text: paragraph.textContent,
        };
      });
    expect(findingLayout.allTextInside).toBeTruthy();
    expect(findingLayout.wrappedLines).toBeGreaterThan(1);
    expect(findingLayout.paragraphScrollWidth).toBeLessThanOrEqual(
      findingLayout.paragraphWidth + 1,
    );
    expect(findingLayout.text).toContain(
      language === "hi"
        ? "हानिकारक गतिविधि का प्रमाण नहीं"
        : "not proof of harmful activity",
    );
  }
});

test("reviewers can publish the supported historical research category", async ({
  page,
}) => {
  await mockRecordClient(page);
  await page.goto("/reviewer");
  await page
    .getByRole("button", { name: "Connect wallet", exact: true })
    .click();
  await page.getByLabel("APK SHA-256", { exact: true }).fill(report.apk_sha256);
  await page
    .getByLabel("Package name", { exact: true })
    .fill(report.package_name);
  await page
    .getByLabel("App display name", { exact: true })
    .fill("Controlled historical sample");
  await page
    .getByLabel("Source reference", { exact: true })
    .fill("https://example.org/research");
  await page
    .getByRole("combobox", { name: "Evidence category", exact: true })
    .selectOption({ label: "Documented historical malware sample" });
  await page
    .getByRole("combobox", { name: "Concern level", exact: true })
    .selectOption("high");
  await page
    .getByLabel("Evidence summary", { exact: true })
    .fill(
      "Controlled historical research attribution; not a real malware report.",
    );
  await page.getByRole("button", { name: "Switch to Hindi" }).click();
  await expect(
    page.getByRole("combobox", { name: "सबूत श्रेणी", exact: true }),
  ).toHaveValue("documented_malware_sample");
  await expect(
    page.getByRole("option", {
      name: "दस्तावेज़ित ऐतिहासिक मैलवेयर नमूना",
      exact: true,
    }),
  ).toHaveCount(1);
  await page.getByRole("button", { name: "Switch to English" }).click();
  await page.getByRole("checkbox").check();
  await page
    .getByRole("button", { name: "Publish to Arkiv", exact: true })
    .click();
  await expect(
    page.getByText("Record published", { exact: true }),
  ).toBeVisible();
  const published = await page.evaluate(
    () =>
      (window as unknown as { __publishedFixture: PublishInput })
        .__publishedFixture,
  );
  expect(published.classification).toBe("documented_malware_sample");
  expect(published.kind).toBe("advisory");
  expect(published.reference_url).toBe("https://example.org/research");
  const entity = await buildEntityInput(published);
  expect(entity.flags.readonly).toBe(true);
});
