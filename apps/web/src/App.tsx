import { useEffect, useRef, useState } from "react";
import type { FormEvent, ChangeEvent } from "react";
import {
  Activity,
  ArrowDownToLine,
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronDown,
  Copy,
  ExternalLink,
  FileCheck2,
  FileUp,
  Fingerprint,
  Globe2,
  Info,
  KeyRound,
  Languages,
  LoaderCircle,
  LockKeyhole,
  Search,
  ShieldCheck,
  ShieldQuestion,
  Smartphone,
  TriangleAlert,
  Upload,
  Wallet,
  X,
} from "lucide-react";
import type { PublishInput } from "@scamsignal/arkiv-client";
import type {
  ArkivResolution,
  Example,
  Language,
  PublicRecord,
  ScanReport,
} from "./types";

const API = (import.meta.env.VITE_API_URL || "").replace(/\/$/, "");
const LIMIT = 50 * 1024 * 1024;
const loadArkiv = () => import("@scamsignal/arkiv-client");
type Phase = "hashing" | "uploading" | "queued" | "processing" | "resolving";
type EvaluatedExample = Example & {
  classification: string;
  sourceUrl: string;
  evidenceUrls: string[];
  evidenceConfidence: string;
  malwareFamily: string;
  evidenceHash?: { algorithm: string; value: string };
};
const unavailable: ArkivResolution = {
  status: "unavailable",
  passport: { status: "incomplete", records: [] },
  warnings: [],
  ignored_count: 0,
};
const textOf = (record: PublicRecord, field: string, fallback = "") => {
  const direct = record[field];
  if (typeof direct === "string") return direct;
  const payload = record.payload || record.data;
  if (payload && typeof payload === "object" && field in payload)
    return String((payload as Record<string, unknown>)[field]);
  return fallback;
};
const short = (value: string, length = 10) =>
  value.length > length * 2
    ? `${value.slice(0, length)}…${value.slice(-length)}`
    : value;
const readableDate = (value: string | number | undefined) => {
  if (!value) return "Not provided";
  const time =
    typeof value === "number" ? (value < 1e12 ? value * 1000 : value) : value;
  const date = new Date(time);
  return Number.isNaN(date.getTime())
    ? String(value)
    : date.toLocaleDateString("en-IN", {
        day: "numeric",
        month: "short",
        year: "numeric",
      });
};

export default function App() {
  const [path, setPath] = useState(window.location.pathname);
  const [language, setLanguage] = useState<Language>("en");
  const [examples, setExamples] = useState<EvaluatedExample[]>([]);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [resolution, setResolution] = useState<ArkivResolution | null>(null);
  const [phase, setPhase] = useState<Phase | null>(null);
  const [error, setError] = useState("");
  const [fileName, setFileName] = useState("");
  const [source, setSource] = useState<"upload" | "example">("upload");
  const abortRef = useRef<AbortController | null>(null);
  const refreshReportRef = useRef<(() => void) | null>(null);
  const activeJobRef = useRef<{ scan_id: string; access_token: string } | null>(
    null,
  );
  const tr = (en: string, hi: string) => (language === "hi" ? hi : en);
  const contextCase = examples.find(
    (example) =>
      example.id === "faketurk" &&
      example.classification === "documented-malware-sample" &&
      example.report.signature.status === "verified" &&
      example.report.coverage.manifest &&
      !example.report.permissions.some(
        (permission) => permission.category === "sensitive",
      ),
  );

  useEffect(() => {
    const change = () => setPath(window.location.pathname);
    window.addEventListener("popstate", change);
    const controller = new AbortController();
    fetch("/data/evaluation.json", { signal: controller.signal })
      .then((r) => (r.ok ? r.json() : []))
      .then((data) => {
        const rows = Array.isArray(data)
          ? data
          : data.results || data.applications || data.samples || [];
        setExamples(
          rows
            .filter(
              (item: Record<string, unknown>) => item.report || item.apk_sha256,
            )
            .map((item: Record<string, unknown>, i: number) => {
              const sample = (item.report || item) as ScanReport;
              return {
                id: String(item.id || i),
                label: String(
                  item.label ||
                    item.name ||
                    sample.app_name ||
                    sample.package_name,
                ),
                context: String(
                  item.context ||
                    item.ground_truth_note ||
                    item.description ||
                    "",
                ),
                classification: String(item.classification || "unclassified"),
                sourceUrl: /^https?:\/\//i.test(String(item.source_url || ""))
                  ? String(item.source_url)
                  : "",
                evidenceUrls: Array.isArray(item.evidence_urls)
                  ? item.evidence_urls.filter(
                      (url): url is string =>
                        typeof url === "string" && /^https?:\/\//i.test(url),
                    )
                  : [],
                evidenceConfidence: String(item.evidence_confidence || ""),
                malwareFamily: String(item.malware_family || ""),
                evidenceHash:
                  item.evidence_hash && typeof item.evidence_hash === "object"
                    ? {
                        algorithm: String(
                          (item.evidence_hash as Record<string, unknown>)
                            .algorithm || "",
                        ),
                        value: String(
                          (item.evidence_hash as Record<string, unknown>)
                            .value || "",
                        ),
                      }
                    : undefined,
                report: sample,
              };
            }),
        );
      })
      .catch(() => {});
    return () => {
      window.removeEventListener("popstate", change);
      controller.abort();
      abortRef.current?.abort();
    };
  }, []);
  useEffect(() => {
    document.documentElement.lang = language;
  }, [language]);
  const navigate = (next: string) => {
    window.history.pushState({}, "", next);
    setPath(next);
    window.scrollTo({ top: 0 });
  };
  function deletePrivateJob() {
    const job = activeJobRef.current;
    activeJobRef.current = null;
    if (job)
      fetch(`${API}/api/scans/${encodeURIComponent(job.scan_id)}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${job.access_token}` },
      }).catch(() => {});
  }

  async function lookup(scan: ScanReport) {
    try {
      return (await (
        await loadArkiv()
      ).resolveReport(scan)) as unknown as ArkivResolution;
    } catch (e) {
      return {
        ...unavailable,
        error:
          e instanceof Error
            ? e.message
            : "The public record network is unavailable.",
      };
    }
  }
  useEffect(() => {
    if (!report) return;
    let disposed = false,
      refreshing = false;
    let debounce: number | undefined;
    async function refresh() {
      if (refreshing || disposed) return;
      refreshing = true;
      setResolution(null);
      const next = await lookup(report!);
      if (!disposed) setResolution(next);
      refreshing = false;
    }
    refreshReportRef.current = refresh;
    let stop: (() => void) | undefined;
    loadArkiv()
      .then((client) => {
        if (disposed) return;
        try {
          stop = client.watchRecords(() => {
            clearTimeout(debounce);
            debounce = window.setTimeout(refresh, 350);
          });
        } catch {
          /* Periodic reads remain available if WebSocket setup fails. */
        }
      })
      .catch(() => {});
    const timer = window.setInterval(refresh, 60000);
    return () => {
      disposed = true;
      refreshReportRef.current = null;
      clearTimeout(debounce);
      clearInterval(timer);
      stop?.();
    };
  }, [report]);
  useEffect(() => {
    if (!report || resolution?.status !== "available") return;
    const expires = [...resolution.passport.records, ...resolution.warnings]
      .map((record) => new Date(record.expires_at || "").getTime())
      .filter(Number.isFinite);
    if (!expires.length) return;
    const timer = window.setTimeout(
      () => {
        setResolution(null);
        refreshReportRef.current?.();
      },
      Math.min(
        2147483647,
        Math.max(1000, Math.min(...expires) - Date.now() + 1),
      ),
    );
    return () => clearTimeout(timer);
  }, [report, resolution]);
  async function openExample(example: Example) {
    abortRef.current?.abort();
    deletePrivateJob();
    const controller = new AbortController();
    abortRef.current = controller;
    setError("");
    setSource("example");
    setFileName(example.label);
    setReport(example.report);
    setResolution(null);
    setPhase("resolving");
    const result = await lookup(example.report);
    if (!controller.signal.aborted) {
      setResolution(result);
      setPhase(null);
      document
        .getElementById("report")
        ?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }
  async function upload(file: File) {
    if (!file.name.toLowerCase().endsWith(".apk")) {
      setError(
        tr(
          "Choose an Android .apk file. Split APK bundles and .aab files are not supported yet.",
          "Android .apk फ़ाइल चुनें। अभी split APK और .aab फ़ाइलें समर्थित नहीं हैं।",
        ),
      );
      return;
    }
    if (file.size > LIMIT) {
      setError(
        tr(
          "This APK is larger than 50 MB. Choose a smaller file for this demo.",
          "यह APK 50 MB से बड़ा है। इस डेमो के लिए छोटी फ़ाइल चुनें।",
        ),
      );
      return;
    }
    if (file.size === 0) {
      setError(
        tr(
          "This file is empty. Choose a complete APK.",
          "यह फ़ाइल खाली है। पूरी APK फ़ाइल चुनें।",
        ),
      );
      return;
    }
    abortRef.current?.abort();
    deletePrivateJob();
    const controller = new AbortController();
    abortRef.current = controller;
    setSource("upload");
    setFileName(file.name);
    setError("");
    setReport(null);
    setResolution(null);
    setPhase("hashing");
    try {
      const digest = await crypto.subtle.digest(
        "SHA-256",
        await file.arrayBuffer(),
      );
      const browserHash = Array.from(new Uint8Array(digest), (n) =>
        n.toString(16).padStart(2, "0"),
      ).join("");
      if (controller.signal.aborted) return;
      setPhase("uploading");
      const form = new FormData();
      form.append("file", file);
      const response = await fetch(`${API}/api/scans`, {
        method: "POST",
        body: form,
        signal: controller.signal,
      });
      const job = await response.json().catch(() => ({}));
      if (!response.ok)
        throw new Error(
          typeof job.detail === "string"
            ? job.detail
            : job.error ||
              `Upload could not finish (${response.status}). Please try again.`,
        );
      if (!job.scan_id || !job.access_token)
        throw new Error(
          "The scan service returned an incomplete job. Please try again.",
        );
      activeJobRef.current = {
        scan_id: job.scan_id,
        access_token: job.access_token,
      };
      setPhase("queued");
      const deadline = Date.now() + 5 * 60 * 1000;
      while (!controller.signal.aborted && Date.now() < deadline) {
        const result = await fetch(
          `${API}/api/scans/${encodeURIComponent(job.scan_id)}`,
          {
            headers: { Authorization: `Bearer ${job.access_token}` },
            signal: controller.signal,
          },
        );
        const status = await result.json().catch(() => ({}));
        if (!result.ok)
          throw new Error(
            typeof status.detail === "string"
              ? status.detail
              : "The scan could not be retrieved. Please try uploading again.",
          );
        if (status.status === "failed")
          throw new Error(
            status.error ||
              "This APK could not be inspected. It may be incomplete or unsupported.",
          );
        if (status.status === "completed" && status.report) {
          const scan = status.report as ScanReport;
          if (scan.apk_sha256.toLowerCase() !== browserHash)
            throw new Error(
              "The analyzed file does not match the uploaded file. The report has been withheld.",
            );
          setReport(scan);
          setPhase("resolving");
          const publicRecords = await lookup(scan);
          if (controller.signal.aborted) return;
          setResolution(publicRecords);
          setPhase(null);
          document
            .getElementById("report")
            ?.scrollIntoView({ behavior: "smooth", block: "start" });
          return;
        }
        setPhase(status.status === "queued" ? "queued" : "processing");
        await new Promise<void>((resolve, reject) => {
          const timer = window.setTimeout(resolve, 1200);
          controller.signal.addEventListener(
            "abort",
            () => {
              clearTimeout(timer);
              reject(new DOMException("Aborted", "AbortError"));
            },
            { once: true },
          );
        });
      }
      if (!controller.signal.aborted)
        throw new Error(
          "The scan took longer than expected. Please retry with a smaller APK.",
        );
    } catch (e) {
      if (!controller.signal.aborted) {
        setError(
          e instanceof Error
            ? e.message
            : "The scan service is unavailable. Please try again.",
        );
        setPhase(null);
      }
    }
  }
  const reset = () => {
    abortRef.current?.abort();
    deletePrivateJob();
    setPhase(null);
    setReport(null);
    setResolution(null);
    setError("");
  };

  return (
    <>
      <a className="skip-link" href="#main">
        {tr("Skip to content", "मुख्य सामग्री पर जाएँ")}
      </a>
      <header className="site-header">
        <div className="header-inner">
          <a
            className="brand"
            href="/"
            onClick={(e) => {
              if (!e.metaKey && !e.ctrlKey) {
                e.preventDefault();
                navigate("/");
              }
            }}
            aria-label="ScamSignal home"
          >
            <span className="brand-mark">
              <img src="/brand/scamsignal-mark.png" alt="" />
            </span>
            <span>
              ScamSignal<span className="brand-sub">AppPassport inside</span>
            </span>
          </a>
          <nav aria-label="Main navigation">
            <a
              className={path === "/" ? "active" : ""}
              href="/"
              onClick={(e) => {
                e.preventDefault();
                navigate("/");
              }}
            >
              {tr("Check an APK", "APK जाँचें")}
            </a>
            <a
              className={path === "/viewer" ? "active" : ""}
              href="/viewer"
              onClick={(e) => {
                e.preventDefault();
                navigate("/viewer");
              }}
            >
              {tr("Public records", "सार्वजनिक रिकॉर्ड")}
            </a>
            <a
              className={`reviewer-nav ${path === "/reviewer" ? "active" : ""}`}
              href="/reviewer"
              onClick={(e) => {
                e.preventDefault();
                navigate("/reviewer");
              }}
            >
              {tr("For reviewers", "समीक्षकों के लिए")}
            </a>
          </nav>
          <button
            className="language-button"
            onClick={() => setLanguage(language === "en" ? "hi" : "en")}
            aria-label={
              language === "en" ? "Switch to Hindi" : "Switch to English"
            }
          >
            <Languages size={17} />
            {language === "en" ? "हिन्दी" : "English"}
          </button>
        </div>
      </header>
      <main id="main">
        {path === "/viewer" ? (
          <PublicViewer language={language} examples={examples} />
        ) : path === "/reviewer" ? (
          <Reviewer language={language} />
        ) : (
          <>
            <section className="intro container">
              <div className="intro-copy">
                <div className="location-note">
                  <span className="location-dot" />
                  {tr(
                    "Built for India. Open to everyone.",
                    "भारत के लिए बना। सबके लिए खुला।",
                  )}
                </div>
                <h1>
                  {tr("Check before", "इंस्टॉल करने से")}
                  <br />
                  {tr("you install.", "पहले जाँचें।")}
                </h1>
                <p>
                  {tr(
                    "One Android app. See who signed it, what it requests, and what trusted reviewers know.",
                    "एक Android ऐप। देखें कि हस्ताक्षर किसके हैं, वह क्या माँगता है और विश्वसनीय समीक्षकों को क्या पता है।",
                  )}
                </p>
                <div className="intro-assurances">
                  <span>
                    <Check size={15} />
                    {tr("Free to check", "जाँच मुफ़्त है")}
                  </span>
                  <span>
                    <Check size={15} />
                    {tr("No account needed", "खाता ज़रूरी नहीं")}
                  </span>
                  <span>
                    <Check size={15} />
                    {tr("APK stays private", "APK निजी रहती है")}
                  </span>
                </div>
                {contextCase && (
                  <div className="hero-case">
                    <span className="eyebrow">
                      {tr("WHY CONTEXT MATTERS", "संदर्भ क्यों ज़रूरी है")}
                    </span>
                    <p>
                      {tr(
                        "A documented fake BtcTurk APK has a valid signature and requests zero sensitive permissions. The research evidence reveals the phishing.",
                        "दस्तावेज़ित नकली BtcTurk APK के हस्ताक्षर वैध हैं और वह कोई संवेदनशील अनुमति नहीं माँगती। शोध के सबूत फ़िशिंग का खुलासा करते हैं।",
                      )}
                    </p>
                    <button
                      className="text-link"
                      onClick={() => openExample(contextCase)}
                      disabled={!!phase}
                    >
                      {tr("Read this case", "यह मामला पढ़ें")}
                      <ArrowRight size={14} />
                    </button>
                  </div>
                )}
              </div>
            </section>
            <section
              className="scan-layout container"
              aria-label={tr(
                "APK inspection workspace",
                "APK जाँच कार्यक्षेत्र",
              )}
            >
              <div className="scan-workspace">
                <div className="workspace-heading">
                  <div>
                    <h2>{tr("Inspect an APK", "APK की जाँच करें")}</h2>
                    <p>
                      {tr(
                        "One file. Evidence you can understand.",
                        "एक फ़ाइल। सबूत जिन्हें आप समझ सकें।",
                      )}
                    </p>
                  </div>
                  <span className="android-label">
                    <Smartphone size={14} />
                    Android
                  </span>
                </div>
                {phase && !report ? (
                  <Progress
                    phase={phase}
                    fileName={fileName}
                    language={language}
                    onCancel={reset}
                  />
                ) : (
                  <UploadZone
                    disabled={!!phase}
                    onFile={upload}
                    language={language}
                  />
                )}
                {error && (
                  <div className="error-banner" role="alert">
                    <TriangleAlert size={19} />
                    <div>
                      <strong>
                        {tr(
                          "We couldn’t finish this check",
                          "यह जाँच पूरी नहीं हुई",
                        )}
                      </strong>
                      <p>{error}</p>
                    </div>
                    <button
                      className="icon-button"
                      onClick={() => setError("")}
                      aria-label="Dismiss error"
                    >
                      <X size={17} />
                    </button>
                  </div>
                )}
                <div className="privacy-note">
                  <LockKeyhole size={15} />
                  <p>
                    {tr(
                      "Your file is analyzed privately and is never published to Arkiv. Raw APKs are deleted after processing; temporary reports expire after 30 minutes.",
                      "आपकी फ़ाइल निजी तौर पर जाँची जाती है और Arkiv पर प्रकाशित नहीं होती। जाँच के बाद APK हटा दी जाती है; अस्थायी रिपोर्ट 30 मिनट में समाप्त होती है।",
                    )}
                  </p>
                </div>
              </div>
              <aside className="understand-panel">
                <h2>{tr("Understand the evidence", "सबूत को समझें")}</h2>
                <div className="explanation-row">
                  <Fingerprint size={23} />
                  <div>
                    <h3>{tr("Who signed it?", "हस्ताक्षर किसके हैं?")}</h3>
                    <p>
                      {tr(
                        "Compare the exact file with a reviewed reference, beyond the app name and icon.",
                        "ऐप के नाम और आइकन से आगे बढ़कर सटीक फ़ाइल को समीक्षा किए गए संदर्भ से मिलाएँ।",
                      )}
                    </p>
                  </div>
                </div>
                <div className="explanation-row">
                  <KeyRound size={23} />
                  <div>
                    <h3>{tr("What does it request?", "यह क्या माँगता है?")}</h3>
                    <p>
                      {tr(
                        "Understand declared access to SMS, contacts, your microphone, and more.",
                        "SMS, संपर्क, माइक्रोफ़ोन और अन्य घोषित पहुँच को समझें।",
                      )}
                    </p>
                  </div>
                </div>
                <div className="explanation-row">
                  <ShieldCheck size={23} />
                  <div>
                    <h3>
                      {tr(
                        "What do reviewers know?",
                        "समीक्षकों को क्या पता है?",
                      )}
                    </h3>
                    <p>
                      {tr(
                        "Read warnings from accepted publishers, with authorship checked on Arkiv.",
                        "स्वीकृत प्रकाशकों की चेतावनियाँ पढ़ें। लेखक की पहचान Arkiv से जाँची जाती है।",
                      )}
                    </p>
                  </div>
                </div>
                <p className="important-note">
                  <Info size={15} />
                  {tr(
                    "No findings does not mean an app is safe. Static analysis cannot observe every behavior.",
                    "कोई संकेत न मिलना ऐप की सुरक्षा का प्रमाण नहीं है। स्थिर विश्लेषण हर व्यवहार नहीं देख सकता।",
                  )}
                </p>
              </aside>
            </section>
            {report && (
              <ReportView
                report={report}
                resolution={resolution}
                source={source}
                language={language}
                sample={examples.find(
                  (example) => example.report.apk_sha256 === report.apk_sha256,
                )}
                loading={phase === "resolving"}
                onReset={reset}
              />
            )}
            {examples.length > 0 && (
              <EvaluationMatrix
                examples={examples}
                language={language}
                disabled={!!phase}
                onOpen={openExample}
              />
            )}
            <section className="purpose-section container">
              <div className="purpose-left">
                <Globe2 size={25} />
                <h2>
                  {tr(
                    "A public memory for app warnings.",
                    "ऐप चेतावनियों की सार्वजनिक याददाश्त।",
                  )}
                </h2>
              </div>
              <div>
                <p>
                  {tr(
                    "AppPassport records live on Arkiv. Compatible tools can verify the publisher and read existing advisories independently, even when this scan service is offline.",
                    "AppPassport रिकॉर्ड Arkiv पर रहते हैं। इस स्कैन सेवा के ऑफ़लाइन होने पर भी अन्य उपकरण प्रकाशक की पहचान जाँचकर मौजूदा चेतावनियाँ पढ़ सकते हैं।",
                  )}
                </p>
                <a
                  href="/viewer"
                  className="text-link"
                  onClick={(e) => {
                    e.preventDefault();
                    navigate("/viewer");
                  }}
                >
                  {tr("Open the independent viewer", "स्वतंत्र व्यूअर खोलें")}
                  <ArrowRight size={15} />
                </a>
              </div>
            </section>
          </>
        )}
      </main>
      <footer className="site-footer container">
        <div>
          <span className="footer-brand">
            <Activity size={17} />
            ScamSignal
          </span>
          <span>
            {tr("Evidence before installation.", "इंस्टॉलेशन से पहले सबूत।")}
          </span>
        </div>
        <div className="footer-links">
          <a
            href="/demo/scamsignal-explainer.mp4"
            target="_blank"
            rel="noreferrer"
          >
            {tr("Watch the film", "फ़िल्म देखें")}
            <ExternalLink size={12} />
          </a>
          <a href="/demo/scamsignal-app-passport.pptx" download>
            {tr("Pitch deck", "प्रस्तुति")}
            <ArrowDownToLine size={12} />
          </a>
          <a
            href="https://docs.arkiv.network/networks/tiramisu/"
            target="_blank"
            rel="noreferrer"
          >
            Arkiv Tiramisu
            <ExternalLink size={12} />
          </a>
          <details>
            <summary>
              {tr("About & limitations", "जानकारी और सीमाएँ")}
              <ChevronDown size={13} />
            </summary>
            <div className="footer-about">
              {tr(
                "ScamSignal performs static APK inspection. A valid signature proves file integrity and signing identity, not trustworthiness. References are reviewed records, not official endorsements. Evaluation advisories describe cited research samples. Expiry is not a safety clearance or erasure guarantee.",
                "ScamSignal APK का स्थिर निरीक्षण करता है। वैध हस्ताक्षर फ़ाइल और हस्ताक्षर पहचान प्रमाणित करते हैं, भरोसा नहीं। संदर्भ समीक्षा किए गए रिकॉर्ड हैं, आधिकारिक समर्थन नहीं। जाँच की चेतावनियाँ स्रोत सहित शोध नमूनों का वर्णन करती हैं। समाप्ति सुरक्षा या पूर्ण मिटाने की गारंटी नहीं है।",
              )}
            </div>
          </details>
        </div>
      </footer>
    </>
  );
}

function EvaluationMatrix({
  examples,
  language,
  disabled,
  onOpen,
}: {
  examples: EvaluatedExample[];
  language: Language;
  disabled: boolean;
  onOpen: (example: Example) => void;
}) {
  const tr = (en: string, hi: string) => (language === "hi" ? hi : en);
  const [filter, setFilter] = useState("all");
  const [records, setRecords] = useState<Record<
    string,
    ArkivResolution
  > | null>(null);
  const [loading, setLoading] = useState(false);
  const [checkedAt, setCheckedAt] = useState<string | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [recordError, setRecordError] = useState(false);
  const mounted = useRef(true);
  const inFlight = useRef(false);
  const group = (example: EvaluatedExample) =>
    example.classification === "documented-malware-sample"
      ? "malware"
      : example.classification === "intentionally-insecure-training-app"
        ? "training"
        : example.classification === "upstream-open-source-release"
          ? "upstream"
          : "unclassified";
  const groupName = (value: string) =>
    value === "upstream"
      ? tr("Upstream release", "मूल रिलीज़")
      : value === "malware"
        ? tr("Documented malware", "दस्तावेज़ित मैलवेयर")
        : value === "training"
          ? tr("Training control", "प्रशिक्षण नमूना")
          : tr("Unclassified", "वर्ग तय नहीं");
  const totals = {
    upstream: examples.filter((example) => group(example) === "upstream")
      .length,
    malware: examples.filter((example) => group(example) === "malware").length,
    training: examples.filter((example) => group(example) === "training")
      .length,
  };
  const signedMalware = examples.filter(
    (example) =>
      group(example) === "malware" &&
      example.report.signature.status === "verified",
  ).length;
  const visible = examples.filter(
    (example) => filter === "all" || group(example) === filter,
  );
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  async function readEvidence() {
    if (inFlight.current) return;
    inFlight.current = true;
    setLoading(true);
    setEnabled(true);
    let deadline: number | undefined;
    try {
      const next = await Promise.race([
        (async () => {
          const client = await loadArkiv();
          const data = await client.listPublicRecords();
          return Object.fromEntries(
            examples.map((example) => [
              example.id,
              client.resolveRecords(
                example.report,
                data.records,
                data.ignored_count,
              ) as unknown as ArkivResolution,
            ]),
          );
        })(),
        new Promise<never>((_, reject) => {
          deadline = window.setTimeout(
            () => reject(new Error("Public lookup timed out.")),
            30000,
          );
        }),
      ]);
      if (mounted.current) {
        setRecords(next);
        setCheckedAt(new Date().toISOString());
        setRecordError(false);
      }
    } catch {
      if (mounted.current) {
        setRecords(null);
        setRecordError(true);
      }
    } finally {
      clearTimeout(deadline);
      inFlight.current = false;
      if (mounted.current) setLoading(false);
    }
  }
  useEffect(() => {
    if (!enabled) return;
    const timer = window.setInterval(readEvidence, 60000);
    return () => clearInterval(timer);
  }, [enabled, examples]);
  useEffect(() => {
    if (!records) return;
    const expires = Object.values(records)
      .flatMap((value) => [...value.passport.records, ...value.warnings])
      .map((record) => new Date(record.expires_at || "").getTime())
      .filter(Number.isFinite);
    if (!expires.length) return;
    const timer = window.setTimeout(
      readEvidence,
      Math.min(
        2147483647,
        Math.max(1000, Math.min(...expires) - Date.now() + 1),
      ),
    );
    return () => clearTimeout(timer);
  }, [records, examples]);
  const passportName = (value: ArkivResolution | undefined) =>
    loading
      ? tr("Checking…", "जाँच जारी…")
      : recordError
        ? tr("Unavailable", "उपलब्ध नहीं")
        : !value
          ? tr("Not checked", "अभी नहीं जाँचा")
          : value.passport.status === "exact_match"
            ? tr("Reference matches", "संदर्भ का मिलान")
            : value.passport.status === "signer_mismatch"
              ? tr("Signer differs", "हस्ताक्षर अलग")
              : value.passport.status === "incomplete"
                ? tr("Incomplete", "जाँच अधूरी")
                : tr("No exact match", "सटीक मिलान नहीं");
  return (
    <section
      className="evaluation-section container"
      aria-labelledby="evaluation-title"
    >
      <div className="evaluation-intro">
        <span className="eyebrow">
          {tr("THE EVALUATION COLLECTION", "जाँच के नमूने")}
        </span>
        <h2 id="evaluation-title">
          {tr(
            "Different apps. Observable evidence.",
            "अलग ऐप। देखे जा सकने वाले सबूत।",
          )}
        </h2>
        <p>
          {tr(
            "Compare measured APK reports with documented provenance. Open any report to see the evidence behind each signal.",
            "दस्तावेज़ित स्रोत के साथ APK की मापी गई रिपोर्ट की तुलना करें। हर संकेत का सबूत देखने के लिए रिपोर्ट खोलें।",
          )}
        </p>
      </div>
      <div
        className="evaluation-totals"
        aria-label={tr("Dataset composition", "नमूनों का वर्गीकरण")}
      >
        <span>
          <strong>{totals.upstream}</strong>
          {tr("upstream releases", "मूल रिलीज़")}
        </span>
        <span>
          <strong>{totals.malware}</strong>
          {tr("documented malware samples", "दस्तावेज़ित मैलवेयर नमूने")}
        </span>
        <span>
          <strong>{totals.training}</strong>
          {tr("training controls", "प्रशिक्षण नमूने")}
        </span>
      </div>
      <p className="evaluation-context">
        <Info size={16} />
        {tr(
          "Precomputed static reports. An upstream release is not a safety guarantee; training controls are deliberately vulnerable, not real-world scam cases. Sample APKs are not redistributed here.",
          "पहले से तैयार स्थिर रिपोर्ट। मूल रिलीज़ सुरक्षा की गारंटी नहीं; प्रशिक्षण नमूने जानबूझकर असुरक्षित हैं, वास्तविक घोटाले नहीं। यहाँ नमूनों की APK वितरित नहीं होती।",
        )}
      </p>
      <div className="evaluation-toolbar">
        <div
          className="evaluation-filters"
          aria-label={tr(
            "Filter evaluated applications",
            "जाँचे गए ऐप का वर्ग चुनें",
          )}
        >
          {[
            {
              id: "all",
              name: tr("All apps", "सभी ऐप"),
              count: examples.length,
            },
            {
              id: "upstream",
              name: tr("Upstream releases", "मूल रिलीज़"),
              count: totals.upstream,
            },
            {
              id: "malware",
              name: tr("Documented threats", "दस्तावेज़ित खतरे"),
              count: totals.malware,
            },
            {
              id: "training",
              name: tr("Training controls", "प्रशिक्षण नमूने"),
              count: totals.training,
            },
          ].map((item) => (
            <button
              key={item.id}
              type="button"
              aria-pressed={filter === item.id}
              onClick={() => setFilter(item.id)}
            >
              {item.name}
              <span>{item.count}</span>
            </button>
          ))}
        </div>
        <button
          className="button secondary evidence-check"
          disabled={loading}
          onClick={readEvidence}
        >
          {loading ? (
            <LoaderCircle size={15} className="spin" />
          ) : (
            <Globe2 size={15} />
          )}
          {enabled
            ? tr("Refresh Arkiv evidence", "Arkiv सबूत फिर जाँचें")
            : tr("Check Arkiv evidence", "Arkiv के सबूत जाँचें")}
        </button>
      </div>
      {enabled && (
        <p
          className={`evaluation-freshness ${recordError ? "lookup-failed" : ""}`}
          role="status"
        >
          {loading
            ? tr(
                "Reading current published Arkiv records…",
                "Arkiv के मौजूदा रिकॉर्ड पढ़े जा रहे हैं…",
              )
            : recordError
              ? tr(
                  "Arkiv lookup unavailable. Record absence has not been established.",
                  "Arkiv की खोज उपलब्ध नहीं। रिकॉर्ड की अनुपस्थिति तय नहीं हुई है।",
                )
              : `${tr("Arkiv snapshot checked", "Arkiv रिकॉर्ड जाँच का समय")} ${new Date(checkedAt || "").toLocaleTimeString(language === "hi" ? "hi-IN" : "en-IN")} · ${tr("refreshes every 60 seconds", "हर 60 सेकंड में नई जाँच")}`}
        </p>
      )}
      <div className="evaluation-table-wrap">
        <table className="evaluation-table">
          <caption className="visually-hidden">
            {tr(
              "Measured reports and current reviewer evidence",
              "मापी गई रिपोर्ट और मौजूदा समीक्षक सबूत",
            )}
          </caption>
          <thead>
            <tr>
              <th scope="col">
                {tr("Application & provenance", "ऐप और स्रोत")}
              </th>
              <th scope="col">{tr("Signature", "हस्ताक्षर")}</th>
              <th scope="col">{tr("Sensitive access", "संवेदनशील पहुँच")}</th>
              <th scope="col">{tr("Observed signals", "देखे गए संकेत")}</th>
              <th scope="col">{tr("Arkiv evidence", "Arkiv के सबूत")}</th>
              <th scope="col">
                <span className="visually-hidden">
                  {tr("Open report", "रिपोर्ट खोलें")}
                </span>
              </th>
            </tr>
          </thead>
          <tbody>
            {visible.map((example) => {
              const value = records?.[example.id];
              const kind = group(example);
              const sensitive = example.report.permissions.filter(
                (permission) => permission.category === "sensitive",
              ).length;
              return (
                <tr key={example.id}>
                  <th scope="row" className="evaluation-app">
                    <strong>{example.label}</strong>
                    <span className={`sample-class ${kind}`}>
                      {groupName(kind)}
                    </span>
                    {example.malwareFamily && (
                      <span className="sample-family">
                        {example.malwareFamily}
                      </span>
                    )}
                    <details className="sample-provenance">
                      <summary>
                        {tr("Source & context", "स्रोत और संदर्भ")}
                        <ChevronDown size={12} />
                      </summary>
                      <p>{example.context}</p>
                      {example.evidenceConfidence && (
                        <p className="provenance-method">
                          {example.evidenceConfidence ===
                          "primary-report-hash-match"
                            ? tr(
                                "Evidence: file hash matched to a primary research report.",
                                "सबूत: फ़ाइल हैश का मूल शोध रिपोर्ट से मिलान।",
                              )
                            : tr(
                                "Evidence: research collection label; independent primary-report attribution has not been established.",
                                "सबूत: शोध संग्रह का लेबल; स्वतंत्र मूल रिपोर्ट से पुष्टि नहीं हुई।",
                              )}
                        </p>
                      )}
                      {example.sourceUrl && (
                        <a
                          href={example.sourceUrl}
                          target="_blank"
                          rel="noreferrer"
                        >
                          {tr("Source reference", "मूल स्रोत")}
                          <ExternalLink size={11} />
                        </a>
                      )}
                      {example.evidenceUrls
                        .filter((url) => url !== example.sourceUrl)
                        .map((url, index) => (
                          <a
                            key={url}
                            href={url}
                            target="_blank"
                            rel="noreferrer"
                          >
                            {tr("Research evidence", "शोध सबूत")} {index + 1}
                            <ExternalLink size={11} />
                          </a>
                        ))}
                      {example.evidenceHash && (
                        <p className="reported-ioc">
                          {tr("Primary report IOC", "मूल रिपोर्ट का IOC")} ·{" "}
                          {example.evidenceHash.algorithm.toUpperCase()}
                          <code>{example.evidenceHash.value}</code>
                        </p>
                      )}
                      <span className="sample-hash-label">
                        {tr("Analyzed APK SHA-256", "जाँची गई APK का SHA-256")}
                      </span>
                      <code>{example.report.apk_sha256}</code>
                    </details>
                  </th>
                  <td data-label={tr("Signature", "हस्ताक्षर")}>
                    <span className="matrix-value">
                      {example.report.signature.status === "verified" ? (
                        <>
                          <CheckCircle2 size={14} />
                          {tr("Verified", "सत्यापित")}
                        </>
                      ) : example.report.signature.status === "invalid" ? (
                        <>
                          <TriangleAlert size={14} />
                          {tr("Invalid", "अमान्य")}
                        </>
                      ) : (
                        <>
                          <Info size={14} />
                          {tr("Unavailable", "उपलब्ध नहीं")}
                        </>
                      )}
                    </span>
                  </td>
                  <td data-label={tr("Sensitive access", "संवेदनशील पहुँच")}>
                    <span className="matrix-value">
                      {example.report.coverage.manifest
                        ? `${sensitive} ${tr("declared", "घोषित")}`
                        : tr("Not inspected", "जाँच नहीं हुई")}
                    </span>
                  </td>
                  <td data-label={tr("Observed signals", "देखे गए संकेत")}>
                    <span className="matrix-value">
                      {example.report.findings.length}{" "}
                      {tr("findings", "निष्कर्ष")}
                    </span>
                  </td>
                  <td data-label={tr("Arkiv evidence", "Arkiv के सबूत")}>
                    <span className="matrix-value">{passportName(value)}</span>
                    <span className="matrix-warning-count">
                      {!loading && !recordError && value
                        ? `${value.warnings.length} ${tr("active warnings", "सक्रिय चेतावनियाँ")}`
                        : tr("Reviewer records", "समीक्षक रिकॉर्ड")}
                    </span>
                  </td>
                  <td className="matrix-action">
                    <button
                      className="example-button"
                      disabled={disabled}
                      onClick={() => onOpen(example)}
                      aria-label={`${tr("Read", "पढ़ें")} ${example.label} ${tr("report", "रिपोर्ट")}`}
                    >
                      {tr("Read report", "रिपोर्ट पढ़ें")}
                      <span className="visually-hidden"> {example.label}</span>
                      <ArrowRight size={15} />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {!visible.length && (
          <p className="empty-collection">
            {tr(
              "No evaluated samples in this category yet.",
              "इस वर्ग में अभी जाँचे गए नमूने नहीं हैं।",
            )}
          </p>
        )}
      </div>
      <div className="evaluation-insight">
        <Fingerprint size={20} />
        <div>
          <h3>
            {tr(
              "A valid signature is one piece of evidence.",
              "वैध हस्ताक्षर सबूत का एक हिस्सा है।",
            )}
          </h3>
          <p>
            {signedMalware > 0
              ? tr(
                  `${signedMalware} documented malware sample(s) in this collection have verified signatures. Signing integrity does not establish trustworthy behavior.`,
                  `इस संग्रह के ${signedMalware} दस्तावेज़ित मैलवेयर नमूनों के हस्ताक्षर सत्यापित हैं। हस्ताक्षर की अखंडता भरोसेमंद व्यवहार तय नहीं करती।`,
                )
              : tr(
                  "Signatures identify the signer and protect file integrity. Permissions describe requested access. Reviewer records add provenance and context. Each answers a different question.",
                  "हस्ताक्षर लेखक की पहचान और फ़ाइल की अखंडता बताते हैं। अनुमतियाँ माँगी गई पहुँच बताती हैं। समीक्षक रिकॉर्ड स्रोत और संदर्भ जोड़ते हैं। हर जाँच एक अलग सवाल का जवाब देती है।",
                )}
          </p>
        </div>
      </div>
    </section>
  );
}

function UploadZone({
  onFile,
  disabled,
  language,
}: {
  onFile: (file: File) => void;
  disabled: boolean;
  language: Language;
}) {
  const [dragging, setDragging] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const tr = (en: string, hi: string) => (language === "hi" ? hi : en);
  return (
    <div
      className={`upload-zone ${dragging ? "dragging" : ""}`}
      onDragOver={(e) => {
        e.preventDefault();
        if (!disabled) setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        if (!disabled && e.dataTransfer.files[0])
          onFile(e.dataTransfer.files[0]);
      }}
    >
      <div className="upload-icon">
        <FileUp size={31} strokeWidth={1.5} />
      </div>
      <h3>{tr("Drop your APK here", "अपनी APK यहाँ डालें")}</h3>
      <p>
        {tr(
          "or choose a file from your phone or computer",
          "या अपने फ़ोन या कंप्यूटर से फ़ाइल चुनें",
        )}
      </p>
      <input
        ref={input}
        className="visually-hidden"
        type="file"
        accept=".apk,application/vnd.android.package-archive"
        aria-label={tr("Choose APK file", "APK फ़ाइल चुनें")}
        disabled={disabled}
        onChange={(e: ChangeEvent<HTMLInputElement>) => {
          const file = e.target.files?.[0];
          if (file) onFile(file);
          e.target.value = "";
        }}
      />
      <button
        className="button primary"
        disabled={disabled}
        onClick={() => input.current?.click()}
      >
        <Upload size={17} />
        {tr("Choose an APK", "APK चुनें")}
        <ArrowRight size={17} />
      </button>
      <span className="file-constraint">
        .apk · {tr("up to 50 MB", "अधिकतम 50 MB")}
      </span>
    </div>
  );
}

function Progress({
  phase,
  fileName,
  language,
  onCancel,
}: {
  phase: Phase;
  fileName: string;
  language: Language;
  onCancel: () => void;
}) {
  const tr = (en: string, hi: string) => (language === "hi" ? hi : en);
  const stages: { id: Phase; label: string }[] = [
    { id: "hashing", label: tr("Identify exact file", "फ़ाइल की पहचान") },
    { id: "uploading", label: tr("Upload privately", "निजी अपलोड") },
    {
      id: "processing",
      label: tr(
        "Inspect signature and permissions",
        "हस्ताक्षर और अनुमतियों की जाँच",
      ),
    },
    {
      id: "resolving",
      label: tr("Compare public evidence", "सार्वजनिक सबूत मिलाएँ"),
    },
  ];
  const index =
    phase === "queued" ? 2 : stages.findIndex((s) => s.id === phase);
  return (
    <div className="progress-panel" role="status" aria-live="polite">
      <div className="progress-title">
        <span className="progress-symbol">
          <LoaderCircle size={26} />
        </span>
        <div>
          <h3>
            {phase === "queued"
              ? tr("Your file is in the queue", "आपकी फ़ाइल कतार में है")
              : tr("Checking your APK", "आपकी APK जाँची जा रही है")}
          </h3>
          <p>{fileName}</p>
        </div>
      </div>
      <ol className="progress-stages">
        {stages.map((stage, i) => (
          <li
            key={stage.id}
            className={i < index ? "done" : i === index ? "current" : ""}
          >
            <span>{i < index ? <Check size={13} /> : i + 1}</span>
            {stage.label}
          </li>
        ))}
      </ol>
      <button className="text-button" onClick={onCancel}>
        {tr("Cancel this check", "यह जाँच रोकें")}
      </button>
    </div>
  );
}

function ReportView({
  report,
  resolution,
  source,
  sample,
  language,
  loading,
  onReset,
}: {
  report: ScanReport;
  resolution: ArkivResolution | null;
  source: "upload" | "example";
  sample?: EvaluatedExample;
  language: Language;
  loading: boolean;
  onReset?: () => void;
}) {
  const [tab, setTab] = useState<"overview" | "permissions" | "passport">(
    "overview",
  );
  const tr = (en: string, hi: string) => (language === "hi" ? hi : en);
  useEffect(() => {
    setTab("overview");
  }, [report.apk_sha256]);
  const sensitive = report.permissions.filter(
    (p) => p.category === "sensitive",
  );
  const attention =
    sample?.classification === "documented-malware-sample" ||
    report.findings.some(
      (f) => f.severity === "high" || f.severity === "review",
    ) ||
    !!resolution?.warnings.length ||
    resolution?.passport.status === "signer_mismatch";
  const title = attention
    ? tr(
        "Take a closer look before installing.",
        "इंस्टॉल करने से पहले ध्यान से देखें।",
      )
    : resolution?.passport.status === "exact_match"
      ? tr(
          "This file matches a reviewed reference.",
          "यह फ़ाइल समीक्षा किए गए संदर्भ से मेल खाती है।",
        )
      : tr("Here’s what we could verify.", "हम यह सत्यापित कर पाए।");
  function download() {
    const blob = new Blob(
      [
        JSON.stringify(
          {
            analysis: report,
            public_evidence: resolution,
            source,
            evaluation_provenance: sample
              ? {
                  classification: sample.classification,
                  context: sample.context,
                  source_url: sample.sourceUrl,
                  evidence_urls: sample.evidenceUrls,
                  evidence_hash: sample.evidenceHash,
                }
              : undefined,
          },
          null,
          2,
        ),
      ],
      { type: "application/json" },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `scamsignal-${report.apk_sha256.slice(0, 12)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }
  return (
    <section
      id="report"
      className="report-section container"
      aria-label={tr("Inspection report", "जाँच रिपोर्ट")}
    >
      <div className="section-heading">
        <div className="report-heading">
          <span className="report-app-icon">
            <Smartphone size={24} />
          </span>
          <div>
            <h2>
              {sample?.label ||
                report.app_name ||
                report.package_name ||
                tr("Android application", "Android ऐप")}
            </h2>
            <p className="package-name">
              {report.package_name} ·{" "}
              {report.version_name ||
                (report.version_code !== null
                  ? report.version_code
                  : tr("Version not declared", "वर्ज़न घोषित नहीं"))}
            </p>
          </div>
        </div>
        <button className="button secondary download-button" onClick={download}>
          <ArrowDownToLine size={16} />
          {tr("Save report", "रिपोर्ट सहेजें")}
        </button>
      </div>
      {sample && (
        <div
          className={`sample-context-banner ${sample.classification === "documented-malware-sample" ? "documented-threat" : ""}`}
        >
          <Info size={17} />
          <div>
            <strong>
              {sample.classification === "documented-malware-sample"
                ? tr(
                    "Known research sample: documented malware",
                    "पहचाना गया शोध नमूना: दस्तावेज़ित मैलवेयर",
                  )
                : sample.classification ===
                    "intentionally-insecure-training-app"
                  ? tr(
                      "Intentionally vulnerable training control",
                      "जानबूझकर असुरक्षित प्रशिक्षण नमूना",
                    )
                  : tr(
                      "Upstream release used as a provenance control",
                      "स्रोत की जाँच के लिए मूल रिलीज़",
                    )}
            </strong>
            <p>
              {sample.classification === "documented-malware-sample"
                ? tr(
                    "This exact file matches a documented specimen in the evaluation collection. Its threat label comes from cited research, not from permission counts.",
                    "यह सटीक फ़ाइल जाँच संग्रह के दस्तावेज़ित नमूने से मेल खाती है। खतरे का वर्ग संदर्भित शोध से आता है, अनुमति की संख्या से नहीं।",
                  )
                : sample.classification ===
                    "intentionally-insecure-training-app"
                  ? tr(
                      "This sample is designed for security training. It is distinct from the documented malware specimens.",
                      "यह नमूना सुरक्षा प्रशिक्षण के लिए बना है। यह दस्तावेज़ित मैलवेयर नमूनों से अलग है।",
                    )
                  : tr(
                      "The source identifies the upstream project and release. It does not establish safety.",
                      "स्रोत मूल परियोजना और रिलीज़ बताता है। वह सुरक्षा तय नहीं करता।",
                    )}
            </p>
            {(sample.evidenceUrls[0] || sample.sourceUrl) && (
              <a
                href={sample.evidenceUrls[0] || sample.sourceUrl}
                target="_blank"
                rel="noreferrer"
              >
                {tr("Read the source evidence", "मूल स्रोत के सबूत पढ़ें")}
                <ExternalLink size={11} />
              </a>
            )}
          </div>
        </div>
      )}
      <div className={`report-verdict ${attention ? "review" : ""}`}>
        <span className="verdict-icon">
          {attention ? <ShieldQuestion size={28} /> : <FileCheck2 size={28} />}
        </span>
        <div>
          <h3>{title}</h3>
          <p>
            {tr(
              "A report of observable evidence, not a guarantee of safety.",
              "देखे जा सकने वाले सबूतों की रिपोर्ट, सुरक्षा की गारंटी नहीं।",
            )}
          </p>
        </div>
        <span className="source-badge">
          {source === "example"
            ? tr("Precomputed demo", "पूर्वनिर्मित डेमो")
            : tr("Live analysis", "ताज़ा विश्लेषण")}
        </span>
      </div>
      <div className="report-summary">
        <div>
          <span>{tr("APK signature", "APK हस्ताक्षर")}</span>
          <strong>
            {report.signature.status === "verified" ? (
              <>
                <CheckCircle2 size={16} />
                {tr("Verified", "सत्यापित")}
              </>
            ) : report.signature.status === "invalid" ? (
              <>
                <TriangleAlert size={16} />
                {tr("Invalid", "अमान्य")}
              </>
            ) : (
              <>
                <Info size={16} />
                {tr("Unavailable", "उपलब्ध नहीं")}
              </>
            )}
          </strong>
        </div>
        <div>
          <span>{tr("Sensitive permissions", "संवेदनशील अनुमतियाँ")}</span>
          <strong>
            <KeyRound size={16} />
            {report.coverage.manifest
              ? `${sensitive.length} ${tr("declared", "घोषित")}`
              : tr("Not inspected", "जाँच नहीं हुई")}
          </strong>
        </div>
        <div>
          <span>AppPassport</span>
          <strong>
            {loading || !resolution ? (
              <>
                <LoaderCircle className="spin" size={16} />
                {tr("Checking", "जाँच जारी")}
              </>
            ) : resolution.status === "unavailable" ? (
              <>
                <Info size={16} />
                {tr("Lookup unavailable", "खोज उपलब्ध नहीं")}
              </>
            ) : resolution.passport.status === "exact_match" ? (
              <>
                <Fingerprint size={16} />
                {tr("Exact reference match", "सटीक संदर्भ मिलान")}
              </>
            ) : resolution.passport.status === "signer_mismatch" ? (
              <>
                <TriangleAlert size={16} />
                {tr("Signer differs", "हस्ताक्षर अलग")}
              </>
            ) : resolution.passport.status === "incomplete" ? (
              <>
                <Info size={16} />
                {tr("Comparison incomplete", "मिलान अधूरा है")}
              </>
            ) : (
              <>
                <ShieldQuestion size={16} />
                {tr("No exact reference match", "सटीक संदर्भ मिलान नहीं")}
              </>
            )}
          </strong>
        </div>
        <div>
          <span>{tr("Trusted warnings", "विश्वसनीय चेतावनियाँ")}</span>
          <strong>
            <ShieldCheck size={16} />
            {loading || !resolution
              ? tr("Checking", "जाँच जारी")
              : resolution.status === "unavailable"
                ? tr("Lookup unavailable", "खोज उपलब्ध नहीं")
                : resolution.warnings.length
                  ? `${resolution.warnings.length} ${tr("active", "सक्रिय")}`
                  : tr("None found", "कोई नहीं मिली")}
          </strong>
        </div>
      </div>
      <div className="report-tabs" role="tablist" aria-label="Report sections">
        {(
          [
            { id: "overview", name: tr("Findings", "निष्कर्ष") },
            {
              id: "permissions",
              name: `${tr("Permissions", "अनुमतियाँ")} (${report.permissions.length})`,
            },
            {
              id: "passport",
              name: tr("Identity & evidence", "पहचान और सबूत"),
            },
          ] as const
        ).map((item) => (
          <button
            role="tab"
            aria-selected={tab === item.id}
            tabIndex={tab === item.id ? 0 : -1}
            aria-controls={`panel-${item.id}`}
            id={`tab-${item.id}`}
            key={item.id}
            className={tab === item.id ? "selected" : ""}
            onClick={() => setTab(item.id)}
            onKeyDown={(event) => {
              const tabs = Array.from(
                event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>(
                  '[role="tab"]',
                ) || [],
              );
              const current = tabs.indexOf(event.currentTarget);
              const next =
                event.key === "ArrowRight"
                  ? (current + 1) % tabs.length
                  : event.key === "ArrowLeft"
                    ? (current + tabs.length - 1) % tabs.length
                    : event.key === "Home"
                      ? 0
                      : event.key === "End"
                        ? tabs.length - 1
                        : -1;
              if (next >= 0) {
                event.preventDefault();
                tabs[next].focus();
                tabs[next].click();
              }
            }}
          >
            {item.name}
          </button>
        ))}
      </div>
      <div
        className="report-content"
        role="tabpanel"
        tabIndex={0}
        id={`panel-${tab}`}
        aria-labelledby={`tab-${tab}`}
      >
        {tab === "overview" && (
          <>
            <div className="findings-header">
              <h3>{tr("What the file tells us", "फ़ाइल क्या बताती है")}</h3>
              <span>
                {report.findings.length} {tr("findings", "निष्कर्ष")}
              </span>
            </div>
            {report.findings.length ? (
              <div className="finding-list">
                {report.findings.map((f) => (
                  <article className={`finding ${f.severity}`} key={f.id}>
                    <span className="finding-icon">
                      {f.severity === "info" ? (
                        <Info size={19} />
                      ) : (
                        <TriangleAlert size={19} />
                      )}
                    </span>
                    <div>
                      <div className="finding-title">
                        <h4>
                          {language === "hi"
                            ? f.title_hi || f.title_en
                            : f.title_en}
                        </h4>
                        <span className={`status-tag ${f.severity}`}>
                          {f.severity === "high"
                            ? tr("High concern", "गंभीर संकेत")
                            : f.severity === "review"
                              ? tr("Review needed", "समीक्षा चाहिए")
                              : tr("Information", "जानकारी")}
                        </span>
                      </div>
                      <p>
                        {language === "hi"
                          ? f.explanation_hi || f.explanation_en
                          : f.explanation_en}
                      </p>
                      {f.evidence.length > 0 && (
                        <details className="evidence-details">
                          <summary>
                            {tr("View observed evidence", "देखे गए सबूत देखें")}
                            <ChevronDown size={14} />
                          </summary>
                          <ul>
                            {f.evidence.map((e, i) => (
                              <li key={i}>
                                <code>{e}</code>
                              </li>
                            ))}
                          </ul>
                        </details>
                      )}
                    </div>
                  </article>
                ))}
              </div>
            ) : (
              <div className="empty-evidence">
                <FileCheck2 size={27} />
                <h4>
                  {tr(
                    "No indicators in the completed checks",
                    "पूरी हुई जाँचों में कोई संकेत नहीं",
                  )}
                </h4>
                <p>
                  {tr(
                    "This does not establish that the app is safe. Check its origin and review the coverage below.",
                    "इससे ऐप सुरक्षित साबित नहीं होता। उसका स्रोत और नीचे जाँच का दायरा देखें।",
                  )}
                </p>
              </div>
            )}
            <Warnings
              resolution={resolution}
              loading={loading}
              language={language}
            />
            <Coverage report={report} language={language} />
          </>
        )}
        {tab === "permissions" && (
          <>
            <div className="findings-header">
              <h3>
                {tr("Access declared by this APK", "इस APK की घोषित पहुँच")}
              </h3>
              <span>
                {sensitive.length} {tr("sensitive", "संवेदनशील")}
              </span>
            </div>
            <p className="section-description">
              {tr(
                "Declared access does not mean a permission was granted or used. Consider whether each request fits the app’s purpose.",
                "घोषित पहुँच का मतलब अनुमति मिलना या उपयोग होना नहीं है। देखें कि हर अनुरोध ऐप के काम के लिए उचित है या नहीं।",
              )}
            </p>
            <div className="permission-list">
              {report.permissions.map((permission) => (
                <div className="permission-row" key={permission.name}>
                  <span className={`permission-icon ${permission.category}`}>
                    <KeyRound size={17} />
                  </span>
                  <div>
                    <strong>
                      {permission.name.replace("android.permission.", "")}
                    </strong>
                    <p>
                      {language === "hi"
                        ? permission.description_hi || permission.description_en
                        : permission.description_en}
                    </p>
                  </div>
                  <span
                    className={`status-tag ${permission.category === "sensitive" ? "review" : "info"}`}
                  >
                    {permission.category === "sensitive"
                      ? tr("Sensitive", "संवेदनशील")
                      : tr("Standard", "सामान्य")}
                  </span>
                </div>
              ))}
              {!report.permissions.length && (
                <p className="empty-line">
                  {tr(
                    "No declared permissions were extracted.",
                    "कोई घोषित अनुमति नहीं मिली।",
                  )}
                </p>
              )}
            </div>
          </>
        )}
        {tab === "passport" && (
          <>
            <div className="identity-intro">
              <Fingerprint size={27} />
              <div>
                <h3>AppPassport</h3>
                <p>
                  {tr(
                    "The exact file and the identity behind its signature.",
                    "सटीक फ़ाइल और उसके हस्ताक्षर के पीछे की पहचान।",
                  )}
                </p>
              </div>
            </div>
            <dl className="identity-table">
              <div>
                <dt>{tr("Package name", "पैकेज नाम")}</dt>
                <dd>
                  <code>{report.package_name || "Not extracted"}</code>
                </dd>
              </div>
              <div>
                <dt>{tr("Release", "रिलीज़")}</dt>
                <dd>
                  {report.version_name || tr("Not declared", "घोषित नहीं")}
                  {report.version_code !== null && ` (${report.version_code})`}
                </dd>
              </div>
              <div>
                <dt>{tr("APK SHA-256", "APK SHA-256")}</dt>
                <dd>
                  <CopyValue value={report.apk_sha256} />
                </dd>
              </div>
              <div>
                <dt>{tr("Signing certificate", "हस्ताक्षर प्रमाणपत्र")}</dt>
                <dd>
                  {report.signature.signer_sha256.length
                    ? report.signature.signer_sha256.map((signer) => (
                        <CopyValue key={signer} value={signer} />
                      ))
                    : tr("Could not be extracted", "प्राप्त नहीं हुआ")}
                </dd>
              </div>
              <div>
                <dt>{tr("Signature schemes", "हस्ताक्षर विधियाँ")}</dt>
                <dd>
                  {report.signature.schemes.join(", ") ||
                    tr("Not available", "उपलब्ध नहीं")}
                </dd>
              </div>
              <div>
                <dt>{tr("Analyzed", "जाँच का समय")}</dt>
                <dd>{readableDate(report.analyzed_at)}</dd>
              </div>
            </dl>
            <div className="passport-result">
              <h4>
                {tr(
                  "Reviewed artifact references",
                  "समीक्षा किए गए फ़ाइल संदर्भ",
                )}
              </h4>
              {loading ? (
                <p className="inline-loading">
                  <LoaderCircle size={16} />
                  {tr("Querying Arkiv…", "Arkiv से खोज जारी…")}
                </p>
              ) : resolution?.status === "unavailable" ? (
                <p>
                  {tr(
                    "Artifact references could not be queried. Their absence has not been established.",
                    "फ़ाइल संदर्भों की खोज पूरी नहीं हुई। उनकी अनुपस्थिति की पुष्टि नहीं है।",
                  )}
                </p>
              ) : resolution?.passport.records.length ? (
                resolution.passport.records.map((record) => (
                  <RecordDetail
                    key={record.key}
                    record={record}
                    language={language}
                    kind="passport"
                  />
                ))
              ) : (
                <p>
                  {tr(
                    "No accepted reference was found for this file. Its origin is unconfirmed.",
                    "इस फ़ाइल के लिए स्वीकृत संदर्भ नहीं मिला। उसका स्रोत अपुष्ट है।",
                  )}
                </p>
              )}
            </div>
            <Warnings
              resolution={resolution}
              loading={loading}
              language={language}
            />
          </>
        )}
      </div>
      <div className="report-bottom">
        <p>
          <Info size={15} />
          {tr(
            "Review the download source. A valid signature alone does not prove trustworthiness.",
            "डाउनलोड स्रोत की जाँच करें। केवल वैध हस्ताक्षर भरोसे का प्रमाण नहीं है।",
          )}
        </p>
        {onReset && (
          <button className="text-link" onClick={onReset}>
            <ArrowLeft size={15} />
            {tr("Check another APK", "दूसरी APK जाँचें")}
          </button>
        )}
      </div>
    </section>
  );
}

function CopyValue({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="copy-value">
      <code title={value}>{short(value, 14)}</code>
      <button
        className="icon-button"
        aria-label="Copy full value"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1800);
          } catch {
            setCopied(false);
          }
        }}
      >
        {copied ? <Check size={14} /> : <Copy size={14} />}
      </button>
      {copied && (
        <span className="copy-confirmation" role="status">
          Copied
        </span>
      )}
    </span>
  );
}

function Coverage({
  report,
  language,
}: {
  report: ScanReport;
  language: Language;
}) {
  const tr = (en: string, hi: string) => (language === "hi" ? hi : en);
  return (
    <details className="coverage">
      <summary>
        {tr("What this check covers", "इस जाँच का दायरा")}
        <ChevronDown size={16} />
      </summary>
      <div className="coverage-items">
        {(
          [
            {
              field: "manifest",
              label: tr("Manifest inspection", "मैनिफेस्ट जाँच"),
            },
            {
              field: "signature",
              label: tr("Signature verification", "हस्ताक्षर सत्यापन"),
            },
            { field: "dex", label: tr("Code indicators", "कोड संकेत") },
          ] as const
        ).map((item) => (
          <span key={item.field}>
            {report.coverage[item.field] ? (
              <CheckCircle2 size={15} />
            ) : (
              <Info size={15} />
            )}
            {item.label}:{" "}
            {report.coverage[item.field]
              ? tr("completed", "पूरी हुई")
              : tr("not completed", "पूरी नहीं हुई")}
          </span>
        ))}
      </div>
      <ul>
        {report.coverage.notes.map((note, i) => (
          <li key={i}>{note}</li>
        ))}
      </ul>
      <p>
        {tr(
          "The APK was not installed or executed. Downloaded code and later behavior may not be visible in this check.",
          "APK को इंस्टॉल या चलाया नहीं गया। बाद में डाउनलोड होने वाला कोड और व्यवहार इस जाँच में नहीं दिख सकता।",
        )}
      </p>
    </details>
  );
}

function Warnings({
  resolution,
  loading,
  language,
}: {
  resolution: ArkivResolution | null;
  loading: boolean;
  language: Language;
}) {
  const tr = (en: string, hi: string) => (language === "hi" ? hi : en);
  return (
    <div className="warnings-section">
      <div className="findings-header">
        <h3>
          <ShieldCheck size={18} />
          {tr("Trusted reviewer warnings", "विश्वसनीय समीक्षक चेतावनियाँ")}
        </h3>
        <span className="network-label">
          <span />
          Arkiv
        </span>
      </div>
      {loading || !resolution ? (
        <div className="record-skeleton" aria-label="Loading public records">
          <div />
          <div />
          <div />
        </div>
      ) : resolution.status === "unavailable" ? (
        <div className="network-error" role="status">
          <Info size={19} />
          <div>
            <strong>
              {tr(
                "Public evidence is unavailable right now",
                "सार्वजनिक सबूत अभी उपलब्ध नहीं हैं",
              )}
            </strong>
            <p>
              {tr(
                "Your file analysis is separate. We cannot confirm whether public warnings exist while this lookup is unavailable.",
                "फ़ाइल विश्लेषण अलग है। खोज उपलब्ध न होने पर सार्वजनिक चेतावनियों की मौजूदगी की पुष्टि नहीं हो सकती।",
              )}
            </p>
          </div>
        </div>
      ) : resolution.warnings.length ? (
        resolution.warnings.map((record) => (
          <RecordDetail
            key={record.key}
            record={record}
            language={language}
            kind="warning"
          />
        ))
      ) : (
        <div className="no-warning">
          <ShieldQuestion size={21} />
          <div>
            <strong>
              {tr(
                "No matching active warning found",
                "कोई मेल खाती सक्रिय चेतावनी नहीं मिली",
              )}
            </strong>
            <p>
              {tr(
                "This is a coverage result, not a safety clearance. The file may not have been reviewed.",
                "यह उपलब्ध रिकॉर्ड का परिणाम है, सुरक्षा प्रमाणपत्र नहीं। संभव है फ़ाइल की समीक्षा न हुई हो।",
              )}
            </p>
          </div>
        </div>
      )}
      {!!resolution?.ignored_count && (
        <p className="ignored-records">
          {tr(
            `${resolution.ignored_count} record(s) excluded by the reviewer policy.`,
            `समीक्षक नीति के अनुसार ${resolution.ignored_count} रिकॉर्ड स्वीकार नहीं किए गए।`,
          )}
        </p>
      )}
    </div>
  );
}

function RecordDetail({
  record,
  language,
  kind,
}: {
  record: PublicRecord;
  language: Language;
  kind: "passport" | "warning";
}) {
  const tr = (en: string, hi: string) => (language === "hi" ? hi : en);
  const title = textOf(
    record,
    language === "hi" ? "title_hi" : "title_en",
    textOf(
      record,
      "title",
      textOf(
        record,
        "app_name",
        kind === "warning"
          ? tr("Reviewer advisory", "समीक्षक चेतावनी")
          : tr("Reviewed artifact", "समीक्षा की गई फ़ाइल"),
      ),
    ),
  );
  const description = textOf(
    record,
    language === "hi" ? "explanation_hi" : "explanation_en",
    textOf(
      record,
      "summary",
      textOf(record, "description", textOf(record, "evidence_summary")),
    ),
  );
  return (
    <article className={`public-record ${kind}`}>
      <div className="public-record-heading">
        <h4>{title}</h4>
        <span className="status-tag verified">
          <ShieldCheck size={12} />
          {tr("Accepted creator", "स्वीकृत लेखक")}
        </span>
      </div>
      {description && <p>{description}</p>}
      <dl>
        <div>
          <dt>{tr("Creator wallet", "लेखक का वॉलेट")}</dt>
          <dd>
            <CopyValue value={record.creator || textOf(record, "$creator")} />
          </dd>
        </div>
        <div>
          <dt>{tr("Valid until", "मान्य होने की अवधि")}</dt>
          <dd>{readableDate(record.expires_at)}</dd>
        </div>
      </dl>
      <details className="evidence-details">
        <summary>
          {tr("View public record", "सार्वजनिक रिकॉर्ड देखें")}
          <ChevronDown size={14} />
        </summary>
        <p className="record-key">
          <strong>{tr("Entity key", "एंटिटी कुंजी")}</strong>
          <CopyValue value={record.key} />
        </p>
        <pre>{JSON.stringify(record, null, 2)}</pre>
      </details>
    </article>
  );
}

function PublicViewer({
  language,
  examples,
}: {
  language: Language;
  examples: Example[];
}) {
  const [hash, setHash] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ArkivResolution | null>(null);
  const [error, setError] = useState("");
  const [queriedHash, setQueriedHash] = useState("");
  const [checkedAt, setCheckedAt] = useState<string | null>(null);
  const [streamInterrupted, setStreamInterrupted] = useState(false);
  const mounted = useRef(true);
  const requestNumber = useRef(0);
  const inFlight = useRef(false);
  const lastReadStarted = useRef(0);
  const tr = (en: string, hi: string) => (language === "hi" ? hi : en);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      requestNumber.current++;
    };
  }, []);
  async function readRecords(value: string) {
    if (inFlight.current) return;
    inFlight.current = true;
    lastReadStarted.current = Date.now();
    const currentRequest = ++requestNumber.current;
    setLoading(true);
    setResult(null);
    const report: ScanReport = {
      schema_version: 1,
      apk_sha256: value,
      file_size: 0,
      package_name: "",
      app_name: "",
      version_name: "",
      version_code: 0,
      signature: {
        status: "unavailable",
        signer_sha256: [],
        schemes: [],
        errors: [],
      },
      permissions: [],
      findings: [],
      coverage: { manifest: false, signature: false, dex: false, notes: [] },
      analyzed_at: new Date().toISOString(),
    };
    let deadline: number | undefined;
    try {
      const next = await Promise.race([
        (async () => {
          const client = await loadArkiv();
          const data = await client.listPublicRecords({ apk_sha256: value });
          report.package_name =
            data.records.find((record) => record.kind === "passport")
              ?.package_name ||
            data.records[0]?.package_name ||
            "";
          return client.resolveRecords(
            report,
            data.records,
            data.ignored_count,
          ) as unknown as ArkivResolution;
        })(),
        new Promise<never>((_, reject) => {
          deadline = window.setTimeout(
            () => reject(new Error("Public record query timed out.")),
            30000,
          );
        }),
      ]);
      if (mounted.current && currentRequest === requestNumber.current) {
        setResult(next);
        setCheckedAt(new Date().toISOString());
      }
    } catch {
      if (mounted.current && currentRequest === requestNumber.current)
        setResult({
          ...unavailable,
          error: "The public record network could not be queried.",
        });
    } finally {
      clearTimeout(deadline);
      inFlight.current = false;
      if (mounted.current && currentRequest === requestNumber.current)
        setLoading(false);
    }
  }
  async function query(e?: FormEvent, selectedHash?: string) {
    e?.preventDefault();
    const value = (selectedHash || hash).trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(value)) {
      setError(
        tr(
          "Enter a complete 64-character SHA-256 hash.",
          "पूरा 64-अक्षर SHA-256 हैश दर्ज करें।",
        ),
      );
      return;
    }
    if (inFlight.current) return;
    setHash(value);
    setQueriedHash(value);
    setError("");
    await readRecords(value);
  }
  useEffect(() => {
    if (!queriedHash) return;
    let disposed = false;
    let unsubscribe: (() => void) | undefined;
    let debounce: number | undefined;
    loadArkiv()
      .then((client) => {
        if (disposed) return;
        try {
          unsubscribe = client.watchRecords(
            () => {
              if (disposed) return;
              setStreamInterrupted(false);
              clearTimeout(debounce);
              debounce = window.setTimeout(
                () => readRecords(queriedHash),
                Math.max(350, 15000 - (Date.now() - lastReadStarted.current)),
              );
            },
            () => {
              if (!disposed) setStreamInterrupted(true);
            },
          );
        } catch {
          setStreamInterrupted(true);
        }
      })
      .catch(() => {
        if (!disposed) setStreamInterrupted(true);
      });
    const interval = window.setInterval(() => readRecords(queriedHash), 60000);
    return () => {
      disposed = true;
      unsubscribe?.();
      clearTimeout(debounce);
      clearInterval(interval);
    };
  }, [queriedHash]);
  useEffect(() => {
    if (result?.status !== "available" || !queriedHash) return;
    const expires = [...result.passport.records, ...result.warnings]
      .map((record) => new Date(record.expires_at || "").getTime())
      .filter(Number.isFinite);
    if (!expires.length) return;
    const earliest = Math.min(...expires);
    const timer = window.setTimeout(
      () => readRecords(queriedHash),
      Math.min(2147483647, Math.max(1000, earliest - Date.now() + 1)),
    );
    return () => clearTimeout(timer);
  }, [result, queriedHash]);
  return (
    <div className="viewer-page container">
      <div className="page-intro">
        <span className="page-icon">
          <Globe2 size={25} />
        </span>
        <h1>
          {tr("Public records, independently.", "स्वतंत्र सार्वजनिक रिकॉर्ड।")}
        </h1>
        <p>
          {tr(
            "Look up an exact APK hash in published Arkiv records. This viewer reads evidence without sending an APK to the scan service.",
            "सटीक APK हैश प्रकाशित Arkiv रिकॉर्ड में खोजें। यह व्यूअर APK को स्कैन सेवा पर भेजे बिना सबूत पढ़ता है।",
          )}
        </p>
      </div>
      <form className="hash-form" onSubmit={query}>
        <label htmlFor="apk-hash">{tr("APK SHA-256", "APK SHA-256")}</label>
        <div>
          <input
            id="apk-hash"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            placeholder={tr(
              "Paste the complete file hash",
              "पूरा फ़ाइल हैश पेस्ट करें",
            )}
            value={hash}
            onChange={(e) => setHash(e.target.value)}
            aria-describedby={error ? "hash-error" : undefined}
          />
          <button className="button primary" disabled={loading} type="submit">
            {loading ? (
              <LoaderCircle className="spin" size={17} />
            ) : (
              <Search size={17} />
            )}
            {tr("Find records", "रिकॉर्ड खोजें")}
          </button>
        </div>
        {error && (
          <p id="hash-error" className="field-error" role="alert">
            {error}
          </p>
        )}
      </form>
      {examples.length > 0 && (
        <div className="viewer-examples">
          <span>{tr("Or explore a demo hash:", "या डेमो हैश देखें:")}</span>
          {examples.map((example) => (
            <button
              key={example.id}
              onClick={() => query(undefined, example.report.apk_sha256)}
              disabled={loading}
            >
              {example.label}
              <ArrowRight size={13} />
            </button>
          ))}
        </div>
      )}
      {(result || loading) && (
        <div className="viewer-result">
          <div className="viewer-freshness" role="status">
            <span>
              {loading
                ? tr(
                    "Verifying current records…",
                    "मौजूदा रिकॉर्ड सत्यापित हो रहे हैं…",
                  )
                : result?.status === "available" && checkedAt
                  ? `${tr("Checked", "जाँच का समय")} ${new Date(checkedAt).toLocaleTimeString(language === "hi" ? "hi-IN" : "en-IN")} · ${tr("refreshes every 60 seconds", "हर 60 सेकंड में नई जाँच")}`
                  : tr(
                      "No current verified snapshot",
                      "मौजूदा सत्यापित जानकारी उपलब्ध नहीं",
                    )}
            </span>
            <button
              className="text-link"
              onClick={() => readRecords(queriedHash)}
              disabled={loading}
            >
              {tr("Refresh records", "रिकॉर्ड फिर जाँचें")}
            </button>
          </div>
          {streamInterrupted && (
            <p className="stream-notice">
              {tr(
                "Live updates are interrupted. Timed refreshes continue every 60 seconds.",
                "लाइव अपडेट बाधित हैं। हर 60 सेकंड में नियमित जाँच जारी है।",
              )}
            </p>
          )}
          <p className="viewer-query-hash">
            <span>{tr("Records for APK", "इस APK के रिकॉर्ड")}</span>
            <CopyValue value={queriedHash} />
          </p>
          <h2>{tr("Artifact references", "फ़ाइल संदर्भ")}</h2>
          {result?.passport.records.length
            ? result.passport.records.map((record) => (
                <RecordDetail
                  key={record.key}
                  record={record}
                  kind="passport"
                  language={language}
                />
              ))
            : !loading &&
              result?.status === "available" && (
                <p className="empty-line">
                  {tr(
                    "No accepted artifact reference found for this exact hash.",
                    "इस सटीक हैश के लिए स्वीकृत फ़ाइल संदर्भ नहीं मिला।",
                  )}
                </p>
              )}
          <Warnings resolution={result} loading={loading} language={language} />
        </div>
      )}
      <div className="viewer-explanation">
        <Fingerprint size={23} />
        <div>
          <h3>
            {tr("Why authorship matters", "लेखक की पहचान क्यों ज़रूरी है")}
          </h3>
          <p>
            {tr(
              "Only records from accepted creator wallets are shown. A publisher name inside a record does not establish identity. Corrections and expiry are evaluated before presenting warnings.",
              "केवल स्वीकृत लेखक वॉलेट के रिकॉर्ड दिखाए जाते हैं। रिकॉर्ड में प्रकाशक का नाम पहचान का प्रमाण नहीं है। चेतावनी दिखाने से पहले सुधार और समाप्ति जाँची जाती है।",
            )}
          </p>
        </div>
      </div>
    </div>
  );
}

function Reviewer({ language }: { language: Language }) {
  const [address, setAddress] = useState("");
  const [error, setError] = useState("");
  const [connecting, setConnecting] = useState(false);
  const tr = (en: string, hi: string) => (language === "hi" ? hi : en);
  async function connect() {
    setConnecting(true);
    setError("");
    try {
      setAddress(await (await loadArkiv()).connectReviewer());
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Wallet connection was declined.",
      );
    } finally {
      setConnecting(false);
    }
  }
  return (
    <div className="reviewer-page container">
      <div className="page-intro">
        <span className="page-icon">
          <ShieldCheck size={25} />
        </span>
        <h1>
          {tr("Keep the evidence accountable.", "सबूतों को जवाबदेह रखें।")}
        </h1>
        <p>
          {tr(
            "Reviewers publish artifact references, exact-file advisories, and corrections under their own wallet identity. Consumer checks are always free.",
            "समीक्षक अपनी वॉलेट पहचान से फ़ाइल संदर्भ, सटीक फ़ाइल की चेतावनियाँ और सुधार प्रकाशित करते हैं। उपभोक्ता जाँच हमेशा मुफ़्त है।",
          )}
        </p>
      </div>
      <div className="reviewer-connect">
        <Wallet size={26} />
        <div>
          <h2>
            {address
              ? tr("Wallet connected", "वॉलेट जुड़ गया")
              : tr("Connect your reviewer wallet", "समीक्षक वॉलेट जोड़ें")}
          </h2>
          <p>
            {address
              ? short(address)
              : tr(
                  "Only accepted creator wallets appear in consumer results.",
                  "उपभोक्ता परिणामों में केवल स्वीकृत लेखक वॉलेट दिखते हैं।",
                )}
          </p>
        </div>
        <button
          className="button primary"
          onClick={connect}
          disabled={connecting}
        >
          {connecting ? (
            <LoaderCircle className="spin" size={17} />
          ) : address ? (
            <CheckCircle2 size={17} />
          ) : (
            <Wallet size={17} />
          )}
          {address
            ? tr("Change wallet", "वॉलेट बदलें")
            : tr("Connect wallet", "वॉलेट जोड़ें")}
        </button>
      </div>
      {error && (
        <p className="field-error" role="alert">
          {error}
        </p>
      )}
      {address && <PublishForm language={language} />}
      <div
        id="reviewer-publisher"
        data-wallet={address}
        className="reviewer-policy"
      >
        <ShieldCheck size={23} />
        <div>
          <h3>
            {tr(
              "A published record must have an accountable author.",
              "प्रकाशित रिकॉर्ड का लेखक जवाबदेह होना चाहिए।",
            )}
          </h3>
          <p>
            {tr(
              "A reviewer’s name alone is not trusted. Arkiv records expose the creating wallet, and the client checks it against the public reviewer policy. Demo reviewers represent this project, not an official authority.",
              "केवल समीक्षक का नाम भरोसे का प्रमाण नहीं है। Arkiv रिकॉर्ड में लेखक का वॉलेट होता है, जिसे क्लाइंट सार्वजनिक समीक्षक नीति से जाँचता है। डेमो समीक्षक इस परियोजना का प्रतिनिधित्व करते हैं, किसी आधिकारिक संस्था का नहीं।",
            )}
          </p>
        </div>
      </div>
    </div>
  );
}

function PublishForm({ language }: { language: Language }) {
  const [kind, setKind] = useState<PublishInput["kind"]>("advisory");
  const [values, setValues] = useState({
    hash: "",
    package: "",
    name: "",
    title: "",
    summary: "",
    reference: "",
    signer: "",
    version: "",
    target: "",
    evidence: "",
    classification: "synthetic_demo",
    severity: "review",
    days: "14",
  });
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [published, setPublished] = useState<{
    entityKey: string;
    txHash: string;
  } | null>(null);
  const tr = (en: string, hi: string) => (language === "hi" ? hi : en);
  const change = (name: keyof typeof values, value: string) =>
    setValues((current) => ({ ...current, [name]: value }));
  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setPublished(null);
    if (!confirmed) {
      setError(
        tr(
          "Confirm that this record contains reviewed evidence and no personal data.",
          "पुष्टि करें कि रिकॉर्ड में समीक्षा किए गए सबूत हैं और कोई निजी डेटा नहीं है।",
        ),
      );
      return;
    }
    if (!/^[a-f0-9]{64}$/i.test(values.hash.trim())) {
      setError(
        tr("Provide a complete APK SHA-256 hash.", "पूरा APK SHA-256 हैश दें।"),
      );
      return;
    }
    if (
      kind === "passport" &&
      !values.signer
        .trim()
        .split(/[\s,]+/)
        .every((hash) => /^[a-f0-9]{64}$/i.test(hash))
    ) {
      setError(
        tr(
          "A passport needs complete verified certificate fingerprints.",
          "पासपोर्ट के लिए पूरे सत्यापित प्रमाणपत्र फ़िंगरप्रिंट चाहिए।",
        ),
      );
      return;
    }
    setBusy(true);
    try {
      const result = await (
        await loadArkiv()
      ).publishRecord({
        kind,
        apk_sha256: values.hash.trim().toLowerCase(),
        package_name: values.package.trim(),
        display_name: values.name.trim(),
        title: values.title.trim() || values.name.trim(),
        summary: values.summary.trim(),
        reference_url: values.reference.trim(),
        version_code: values.version ? Number(values.version) : null,
        signer_sha256: values.signer.trim()
          ? values.signer
              .trim()
              .split(/[\s,]+/)
              .map((hash) => hash.toLowerCase())
          : [],
        evidence: values.evidence
          .split("\n")
          .map((line) => line.trim())
          .filter(Boolean),
        classification: values.classification as PublishInput["classification"],
        severity: values.severity as PublishInput["severity"],
        expires_days: Number(values.days),
        ...(kind === "correction"
          ? { target_key: values.target.trim(), action: "retract" as const }
          : {}),
      });
      setPublished({ entityKey: result.entityKey, txHash: result.txHash });
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "The record could not be published.",
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <form className="publish-form" onSubmit={submit}>
      <div className="publish-form-heading">
        <h2>
          {tr("Publish reviewed evidence", "समीक्षा किए गए सबूत प्रकाशित करें")}
        </h2>
        <span className="network-label">
          <span />
          Tiramisu
        </span>
      </div>
      <div className="publish-types" aria-label="Record type">
        {(
          [
            { id: "advisory", label: tr("Advisory", "चेतावनी") },
            { id: "passport", label: "AppPassport" },
            { id: "correction", label: tr("Retraction", "वापसी") },
          ] as const
        ).map((item) => (
          <button
            type="button"
            key={item.id}
            className={kind === item.id ? "selected" : ""}
            onClick={() => {
              setKind(item.id);
              setError("");
              setPublished(null);
              setValues((current) => ({
                ...current,
                days: item.id === "advisory" ? "14" : "30",
              }));
            }}
          >
            {item.label}
          </button>
        ))}
      </div>
      <div className="publish-fields">
        <label>
          {tr("APK SHA-256", "APK SHA-256")}
          <input
            required
            value={values.hash}
            onChange={(e) => change("hash", e.target.value)}
            placeholder="64 hexadecimal characters"
            spellCheck={false}
            autoCapitalize="none"
          />
        </label>
        <label>
          {tr("Package name", "पैकेज नाम")}
          <input
            required
            value={values.package}
            onChange={(e) => change("package", e.target.value)}
            placeholder="org.example.app"
          />
        </label>
        <label>
          {tr("App display name", "ऐप का नाम")}
          <input
            required
            maxLength={120}
            value={values.name}
            onChange={(e) => change("name", e.target.value)}
          />
        </label>
        <label>
          {tr("Source reference", "स्रोत संदर्भ")}
          <input
            required
            type="url"
            value={values.reference}
            onChange={(e) => change("reference", e.target.value)}
            placeholder="https://"
          />
        </label>
        {kind === "passport" && (
          <>
            <label>
              {tr(
                "Verified certificate SHA-256",
                "सत्यापित प्रमाणपत्र SHA-256",
              )}
              <input
                required
                value={values.signer}
                onChange={(e) => change("signer", e.target.value)}
                spellCheck={false}
              />
            </label>
            <label>
              {tr("Version code", "वर्ज़न कोड")}
              <input
                type="number"
                min="0"
                step="1"
                value={values.version}
                onChange={(e) => change("version", e.target.value)}
              />
            </label>
          </>
        )}
        {kind === "correction" && (
          <label className="full-width">
            {tr("Original record entity key", "मूल रिकॉर्ड की एंटिटी कुंजी")}
            <input
              required
              value={values.target}
              onChange={(e) => change("target", e.target.value)}
              placeholder="0x…"
              spellCheck={false}
            />
          </label>
        )}
        <label>
          {tr("Evidence category", "सबूत श्रेणी")}
          <select
            value={values.classification}
            onChange={(e) => change("classification", e.target.value)}
          >
            <option value="synthetic_demo">
              {tr("Synthetic demonstration", "कृत्रिम डेमो")}
            </option>
            <option value="open_source_release">
              {tr("Open source release", "ओपन सोर्स रिलीज़")}
            </option>
            <option value="documented_malware_sample">
              {tr(
                "Documented historical malware sample",
                "दस्तावेज़ित ऐतिहासिक मैलवेयर नमूना",
              )}
            </option>
            <option value="insecure_training_app">
              {tr("Insecure training application", "असुरक्षित प्रशिक्षण ऐप")}
            </option>
          </select>
        </label>
        <label>
          {tr("Record lifetime", "रिकॉर्ड की अवधि")}
          <select
            value={values.days}
            onChange={(e) => change("days", e.target.value)}
          >
            <option value="14">14 {tr("days", "दिन")}</option>
            <option value="30">30 {tr("days", "दिन")}</option>
            <option value="60">60 {tr("days", "दिन")}</option>
          </select>
        </label>
        {kind === "advisory" && (
          <>
            <label>
              {tr("Advisory title", "चेतावनी का शीर्षक")}
              <input
                maxLength={180}
                value={values.title}
                onChange={(e) => change("title", e.target.value)}
              />
            </label>
            <label>
              {tr("Concern level", "संकेत का स्तर")}
              <select
                value={values.severity}
                onChange={(e) => change("severity", e.target.value)}
              >
                <option value="info">{tr("Information", "जानकारी")}</option>
                <option value="review">
                  {tr("Review needed", "समीक्षा चाहिए")}
                </option>
                <option value="high">
                  {tr("High concern", "गंभीर संकेत")}
                </option>
              </select>
            </label>
          </>
        )}
        <label className="full-width">
          {kind === "correction"
            ? tr("Retraction reason", "वापसी का कारण")
            : tr("Evidence summary", "सबूतों का सारांश")}
          <textarea
            required
            rows={4}
            maxLength={3000}
            value={values.summary}
            onChange={(e) => change("summary", e.target.value)}
          />
        </label>
        <label className="full-width">
          {tr(
            "Observed evidence, one item per line",
            "देखे गए सबूत, हर पंक्ति में एक",
          )}
          <textarea
            rows={3}
            value={values.evidence}
            onChange={(e) => change("evidence", e.target.value)}
          />
        </label>
      </div>
      <label className="confirm-publish">
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(e) => setConfirmed(e.target.checked)}
        />
        {tr(
          "I reviewed this evidence. This public record contains no personal data, secrets, or raw APK contents.",
          "मैंने इन सबूतों की समीक्षा की है। सार्वजनिक रिकॉर्ड में निजी डेटा, गोपनीय जानकारी या मूल APK सामग्री नहीं है।",
        )}
      </label>
      <p className="publish-note">
        {tr(
          "Published records are public. Expiry removes them from live queries; it does not guarantee erasure of history. Reviewer writes use testnet gas.",
          "प्रकाशित रिकॉर्ड सार्वजनिक हैं। अवधि पूरी होने पर वे लाइव खोज से हटते हैं, इतिहास मिटने की गारंटी नहीं है। समीक्षक लेखन में टेस्टनेट गैस लगती है।",
        )}
      </p>
      {error && (
        <p className="field-error" role="alert">
          {error}
        </p>
      )}
      {published && (
        <div className="publish-success" role="status">
          <CheckCircle2 size={19} />
          <div>
            <strong>{tr("Record published", "रिकॉर्ड प्रकाशित हुआ")}</strong>
            <CopyValue value={published.entityKey} />
            <a
              href={`https://tiramisu.explorer.arkiv.network/tx/${published.txHash}`}
              target="_blank"
              rel="noreferrer"
            >
              {tr("View transaction", "लेन-देन देखें")}
              <ExternalLink size={13} />
            </a>
          </div>
        </div>
      )}
      <button
        className="button primary"
        type="submit"
        disabled={busy || !confirmed}
      >
        {busy ? (
          <LoaderCircle className="spin" size={16} />
        ) : (
          <ShieldCheck size={16} />
        )}
        {busy
          ? tr(
              "Awaiting wallet and confirmation",
              "वॉलेट और पुष्टि की प्रतीक्षा",
            )
          : tr("Publish to Arkiv", "Arkiv पर प्रकाशित करें")}
      </button>
    </form>
  );
}
