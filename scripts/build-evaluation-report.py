"""Build public PDF/CSV/JSON evidence from the recorded APK evaluation.

Requires reportlab. No APK, credential, or private session data is read.
Run from the repository root: python scripts/build-evaluation-report.py
"""

import csv
import hashlib
import json
import shutil
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output" / "pdf"
PUBLIC = ROOT / "apps" / "web" / "public" / "reports"
OUT.mkdir(parents=True, exist_ok=True)
PUBLIC.mkdir(parents=True, exist_ok=True)
evaluation = json.loads((ROOT / "scanner" / "evaluation.json").read_text(encoding="utf-8"))
live = json.loads((ROOT / "scanner" / "live-evaluation.json").read_text(encoding="utf-8"))
verification = json.loads((ROOT / "arkiv" / "verification.json").read_text(encoding="utf-8"))
evidence = json.loads((ROOT / "arkiv" / "evidence.json").read_text(encoding="utf-8"))
samples = evaluation["samples"]
live_by_id = {s["id"]: s for s in live["samples"]}
chain_by_id = {s["sample"]: s for s in verification["results"]}

if len(samples) != 12 or len({s["id"] for s in samples}) != 12:
    raise ValueError("Expected twelve distinct evaluated samples")
for sample in samples:
    report = sample["report"]
    row = live_by_id[sample["id"]]
    if (report["apk_sha256"] != row["apk_sha256"]
            or report["package_name"] != row["package_name"]
            or report["signature"]["status"] != row["signature"]
            or len(report["permissions"]) != row["permissions"]
            or sum(p["category"] == "sensitive" for p in report["permissions"]) != row["sensitive_permissions"]
            or [f["id"] for f in report["findings"]] != row["finding_ids"]
            or not row["session_auth_checked"] or not row["delete_checked"]):
        raise ValueError(f"Recorded API evidence disagrees for {sample['id']}")
if not verification["passed"] or verification["verified_record_count"] != len(evidence["records"]):
    raise ValueError("Arkiv verification did not pass for the expected records")

GREEN = colors.HexColor("#17634C")
INK = colors.HexColor("#17261E")
MUTED = colors.HexColor("#52625A")
LIGHT = colors.HexColor("#F3F6F1")
RULE = colors.HexColor("#D9E2DA")
AMBER = colors.HexColor("#825423")
font = "Helvetica"
bold = "Helvetica-Bold"
font_path = Path("C:/Windows/Fonts/arial.ttf")
bold_path = Path("C:/Windows/Fonts/arialbd.ttf")
if font_path.exists() and bold_path.exists():
    pdfmetrics.registerFont(TTFont("ReportSans", str(font_path)))
    pdfmetrics.registerFont(TTFont("ReportSansBold", str(bold_path)))
    font, bold = "ReportSans", "ReportSansBold"

styles = getSampleStyleSheet()
styles.add(ParagraphStyle("ReportTitle", fontName=bold, fontSize=34, leading=38, textColor=INK, spaceAfter=18))
styles.add(ParagraphStyle("ReportH1", fontName=bold, fontSize=23, leading=28, textColor=INK, spaceAfter=16))
styles.add(ParagraphStyle("ReportH2", fontName=bold, fontSize=13, leading=17, textColor=GREEN, spaceBefore=12, spaceAfter=8))
styles.add(ParagraphStyle("Body", fontName=font, fontSize=10.5, leading=15.8, textColor=INK, spaceAfter=10))
styles.add(ParagraphStyle("Small", fontName=font, fontSize=8.5, leading=12.3, textColor=MUTED, spaceAfter=6))
styles.add(ParagraphStyle("Label", fontName=bold, fontSize=9, leading=12, textColor=GREEN, spaceAfter=10))
styles.add(ParagraphStyle("Cell", fontName=font, fontSize=8.3, leading=11.2, textColor=INK))
styles.add(ParagraphStyle("CellHead", fontName=bold, fontSize=8.2, leading=10.5, textColor=colors.white))
styles.add(ParagraphStyle("Hash", fontName="Courier", fontSize=7.5, leading=10.2, textColor=INK, spaceAfter=7))
styles.add(ParagraphStyle("Callout", fontName=bold, fontSize=12, leading=17, textColor=INK, spaceAfter=12))


def para(text, style="Body"):
    return Paragraph(text, styles[style])


def link(url, label):
    return f'<link href="{escape(url, quote=True)}" color="#17634C"><u>{escape(label)}</u></link>'


def local_time(value):
    date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return date.astimezone(timezone(timedelta(hours=5, minutes=30))).strftime("%d %B %Y, %H:%M IST")


def hash_text(value):
    # Explicit split keeps fingerprints fully visible at A4 width.
    return escape(value[:32]) + "<br/>" + escape(value[32:])


def classification(sample):
    return {
        "upstream-open-source-release": "Upstream release",
        "documented-malware-sample": "Historical malware",
        "intentionally-insecure-training-app": "Training control",
    }[sample["classification"]]


def source_links(sample):
    urls = [sample["source_url"], *sample.get("evidence_urls", [])]
    return list(dict.fromkeys(urls))


def report_row(sample):
    r = sample["report"]
    lv = live_by_id[sample["id"]]
    ch = chain_by_id[sample["id"]]
    return {
        "id": sample["id"], "application": sample["name"], "release": sample["release"],
        "classification": sample["classification"], "apk_sha256": r["apk_sha256"],
        "package_name": r["package_name"], "signature_status": r["signature"]["status"],
        "signer_sha256": r["signature"]["signer_sha256"], "signature_schemes": r["signature"]["schemes"],
        "declared_permissions": len(r["permissions"]),
        "sensitive_permissions": sum(p["category"] == "sensitive" for p in r["permissions"]),
        "finding_ids": [f["id"] for f in r["findings"]], "api_seconds_recorded": lv["seconds"],
        "session_auth_checked": lv["session_auth_checked"], "report_delete_checked": lv["delete_checked"],
        "passport_match": ch["passport"], "accepted_advisories_at_verification": ch["warning_count"],
        "arkiv_entity_keys": ch["entity_keys"], "source_urls": source_links(sample),
        "classification_basis": sample["ground_truth_note"], "research_ioc": sample.get("evidence_hash"),
    }


rows = [report_row(s) for s in samples]
source_hashes = {
    filename: hashlib.sha256((ROOT / filename).read_bytes()).hexdigest()
    for filename in ["scanner/evaluation.json", "scanner/live-evaluation.json", "arkiv/verification.json", "arkiv/evidence.json"]
}
summary = {
    "schema_version": 1,
    "evaluated_at": evaluation["evaluated_at"], "arkiv_verified_at": verification["verified_at"],
    "network": evidence["network"], "chain_id": evidence["chain_id"],
    "reviewer_creator": evidence["creator_wallet"], "record_count": verification["verified_record_count"],
    "read_block": verification["read_block"], "verification_passed": verification["passed"],
    "method": evaluation["method"], "limitations": evaluation["limitations"],
    "source_file_sha256": source_hashes, "samples": rows,
}
json_path = OUT / "scamsignal-apk-evaluation.json"
json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
csv_path = OUT / "scamsignal-apk-evaluation.csv"
columns = ["id", "application", "release", "classification", "apk_sha256", "package_name", "signature_status",
           "signer_sha256", "signature_schemes", "declared_permissions", "sensitive_permissions", "finding_ids",
           "api_seconds_recorded", "session_auth_checked", "report_delete_checked", "passport_match",
           "accepted_advisories_at_verification", "arkiv_entity_keys", "source_urls", "classification_basis"]
with csv_path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=columns)
    writer.writeheader()
    for row in rows:
        clean = {key: row[key] for key in columns}
        for key, value in clean.items():
            if isinstance(value, list):
                clean[key] = " | ".join(value)
        writer.writerow(clean)

story = []
story += [para("SCAMSIGNAL / APPPASSPORT", "Label"), Spacer(1, 18),
          para("APK evaluation<br/>Evidence report", "ReportTitle"),
          para("Twelve actual public APK uploads. Measured static results, source-backed classifications and live Arkiv verification.", "Callout"),
          para(f"Recorded API run: {local_time(evaluation['evaluated_at'])}<br/>Arkiv verification: {local_time(verification['verified_at'])}", "Small")]
metric_data = [[para("12 APKs", "ReportH2"), para("12 signatures", "ReportH2"), para("19 entities", "ReportH2")],
               [para("5 upstream releases<br/>5 historical malware<br/>2 training controls", "Small"),
                para("All cryptographically verified.<br/>This does not establish safety.", "Small"),
                para("12 artifact passports<br/>7 reviewed advisories<br/>Arkiv Tiramisu testnet", "Small")]]
metric = Table(metric_data, colWidths=[164, 164, 171])
metric.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), LIGHT), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("LEFTPADDING", (0, 0), (-1, -1), 14), ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                           ("TOPPADDING", (0, 0), (-1, 0), 3), ("BOTTOMPADDING", (0, -1), (-1, -1), 12)]))
story += [Spacer(1, 15), metric, Spacer(1, 16), para("What this establishes", "ReportH2"),
          para("The deployed parser and signature verifier processed all twelve samples. The recorded run checked private report authorization and deletion for every upload. Accepted Arkiv records matched the evaluated artifact identities and the expected advisory counts."),
          para("What it does not establish", "ReportH2"),
          para("This is an integration evaluation of selected samples, not a detection-accuracy benchmark. Malware labels come from cited research and exact IOC matches. It does not establish official publisher verification, current Indian campaign coverage, runtime behavior or superiority over Google Play Protect."),
          para(link("https://scamsignal.ajnasnb.com/#evaluation", "Open the public results") + "  |  " + link("https://github.com/AjnasNB/scamsignal", "Open the source repository"), "Small"), PageBreak()]

story += [para("01 / Measured results", "Label"), para("All twelve applications", "ReportH1"),
          para("Permissions are declarations, not observed grants or behavior. 'Sensitive' uses this scanner's classification. A finding is a review signal, not a malware detection.", "Small")]
headers = ["Application / release", "Class", "Total", "Sensitive", "Findings", "Advisories"]
data = [[para(h, "CellHead") for h in headers]]
for s in samples:
    row = report_row(s)
    rel = s["release"].replace("2019 historical research specimen", "2019 research specimen")
    data.append([para(escape(s["name"]) + "<br/><font color='#52625A'>" + escape(rel) + "</font>", "Cell"),
                 para(classification(s), "Cell"), str(row["declared_permissions"]), str(row["sensitive_permissions"]),
                 str(len(row["finding_ids"])), str(row["accepted_advisories_at_verification"])])
table = Table(data, colWidths=[192, 90, 38, 58, 49, 72], repeatRows=1)
table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), GREEN), ("FONTNAME", (0, 1), (-1, -1), font),
                          ("FONTSIZE", (0, 1), (-1, -1), 8.5), ("TEXTCOLOR", (0, 1), (-1, -1), INK),
                          ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
                          ("LINEBELOW", (0, 1), (-1, -1), 0.4, RULE), ("LEFTPADDING", (0, 0), (-1, -1), 8),
                          ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
story += [table, Spacer(1, 15), para("The useful counterexample", "ReportH2"),
          para("The historical Fake BtcTurk phishing specimen has a valid signature and zero permissions classified as sensitive. Its warning is justified by an exact match to primary-research evidence, not by the permission count. Conversely, legitimate upstream releases can declare sensitive capabilities for their purpose."),
          para("The five malware samples cover three historical research campaigns. The two training applications are deliberately vulnerable educational controls, not confirmed scams. All twelve artifact passports matched; a malicious artifact can also have an exact passport match.", "Small"), PageBreak()]

for page_start in range(0, len(samples), 2):
    page_samples = samples[page_start:page_start + 2]
    story += [para("02 / Artifact identities", "Label"),
              para(f"Evidence {page_start + 1:02d}-{page_start + len(page_samples):02d}", "ReportH1")]
    for s in page_samples:
        r = s["report"]
        lv = live_by_id[s["id"]]
        ch = chain_by_id[s["id"]]
        block = [para(escape(s["name"]) + " / " + classification(s), "ReportH2"),
                 para("Package: " + escape(r["package_name"]) + "<br/>Release: " + escape(s["release"]), "Small"),
                 para("APK SHA-256", "Label"), para(hash_text(r["apk_sha256"]), "Hash")]
        for i, signer in enumerate(r["signature"]["signer_sha256"]):
            block += [para(f"Signer certificate SHA-256 ({i + 1})", "Label"), para(hash_text(signer), "Hash")]
        findings = "; ".join(f["title_en"] for f in r["findings"]) or "No static findings"
        block += [para(f"Signature: verified ({', '.join(r['signature']['schemes'])}). Findings: {escape(findings)}.", "Small"),
                  para(f"Recorded API processing: {lv['seconds']:.2f}s. Private authorization and deletion: checked. Artifact match: {escape(ch['passport'])}. Accepted advisories: {ch['warning_count']}.", "Small")]
        block += [para("Sources: " + " | ".join(link(url, f"[{i + 1}] " + ("Primary research" if i and 'welivesecurity' in url else "Source record")) for i, url in enumerate(source_links(s))), "Small")]
        if s.get("evidence_hash"):
            ioc = s["evidence_hash"]
            block += [para("Research IOC (" + escape(ioc["algorithm"].upper()) + "): " + escape(ioc["value"]), "Hash")]
        block += [Spacer(1, 7)]
        story.append(KeepTogether(block))
    story.append(PageBreak())

story += [para("03 / API and public records", "Label"), para("Verification and limits", "ReportH1"),
          para("Static inspection", "ReportH2"), para(escape(evaluation["method"])),
          para("The report is built from recorded results rather than a new malware execution. The parser uses a deployed Linux service; input APKs are never installed or executed. Raw APKs are deleted after processing, and private reports have a 30-minute retention window. The service accepts standalone APK files up to 50 MB."),
          para("Arkiv verification", "ReportH2"),
          para(f"Chain: {escape(evidence['network'])}, ID {evidence['chain_id']}. Checked at block {escape(verification['read_block'])}. {verification['verified_record_count']} of {verification['expected_record_count']} expected records were accepted. Every sample matched its exact reviewed-artifact reference; the five malware and two training samples each had one source-backed advisory."),
          para("Accepted reviewer creator: " + escape(evidence["creator_wallet"]), "Small"),
          para("This creator is a project-controlled evaluation reviewer, not an official APK publisher, bank, government body or independent reviewer community. The client checks protocol creator metadata, readonly creation flags, schema/index binding and expiry. It trusts RPC metadata and does not independently verify state proofs."),
          para("The expiry boundary", "ReportH2"),
          para("A passport match establishes an exact reviewed artifact, not safety. Expired records leave the live query surface; expiry does not mean a threat was resolved, and historical copies may remain. Same-author corrections and retractions are interpreted by the client. A lookup outage is reported as unavailable rather than an empty clean result."),
          para("Excluded measurements", "ReportH2"),
          para("No APK execution, runtime telemetry, deep DEX behavior analysis, signing-key rotation lineage, official publisher binding, sensitivity/specificity measurement or same-sample Play Protect comparison was performed. The recorded processing times are single observations, not latency guarantees."), PageBreak()]

story += [para("04 / Reproduction and sources", "Label"), para("Check the evidence", "ReportH1"),
          para("1. Inspect the public results", "ReportH2"),
          para(link("https://scamsignal.ajnasnb.com/#evaluation", "scamsignal.ajnasnb.com/#evaluation") + ": open a measured report and check current Arkiv evidence. The examples are visibly labelled precomputed static reports; selecting one does not re-upload an APK. A separate file upload creates a fresh private analysis."),
          para("2. Read the recorded dataset", "ReportH2"),
          para("The CSV contains measured counts, identities, source URLs and entity keys. The JSON additionally contains research IOCs, classification basis and source-file digests. The repository retains the full sanitized manifest reports and original recorded API verification."),
          para("3. Re-run the public Arkiv check", "ReportH2"),
          para("Clone the public repository, install dependencies with <b>npm ci</b>, then run <b>npm run arkiv:verify</b>. This reads the published entities and checks accepted authors, artifact binding, classifications, readonly flags, source references and expected warning counts. The default public read gateway requires no consumer wallet. Another operator may configure their own RPC provider with <b>SCAMSIGNAL_READ_RPC_URL</b>. Records must still be live; later expiry can change results."),
          para("4. Reproduce a fresh upstream upload", "ReportH2"),
          para("Use an exact upstream release linked in the evidence pages, calculate its SHA-256, and upload it through the live app. Compare package, complete signer set, permissions and findings. Different releases or distribution channels can produce different hashes and signatures. The public app does not redistribute research malware APKs."),
          para("Dataset and implementation links", "ReportH2")]
for label, url in [
    ("Full measured reports", "https://github.com/AjnasNB/scamsignal/blob/main/scanner/evaluation.json"),
    ("Recorded deployed-API test", "https://github.com/AjnasNB/scamsignal/blob/main/scanner/live-evaluation.json"),
    ("Arkiv verification snapshot", "https://github.com/AjnasNB/scamsignal/blob/main/arkiv/verification.json"),
    ("Published entity keys and transactions", "https://github.com/AjnasNB/scamsignal/blob/main/arkiv/evidence.json"),
    ("Schema and reviewer policy", "https://github.com/AjnasNB/scamsignal/blob/main/arkiv/schema.md"),
    ("Reproducible Arkiv friction report", "https://github.com/AjnasNB/scamsignal/blob/main/arkiv/friction.md"),
]:
    story.append(para(link(url, label), "Small"))
story += [Spacer(1, 12), para("Interpretation", "ReportH2"),
          para("Prefer the organization's official store listing and keep Play Protect enabled. An APK is a package format, not a verdict. This report adds traceable artifact evidence; it never authorizes installation or treats an absent warning as a safety certificate.", "Small")]


def page_chrome(canvas, doc):
    canvas.saveState()
    w, h = A4
    canvas.setFillColor(GREEN)
    canvas.rect(0, h - 7, w, 7, fill=1, stroke=0)
    canvas.setStrokeColor(RULE)
    canvas.line(48, 44, w - 48, 44)
    canvas.setFont(font, 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(48, 29, "ScamSignal + AppPassport / APK evaluation / 11 October 2026")
    canvas.drawRightString(w - 48, 29, str(doc.page))
    canvas.restoreState()


pdf_path = OUT / "scamsignal-apk-evaluation.pdf"
doc = SimpleDocTemplate(str(pdf_path), pagesize=A4, rightMargin=48, leftMargin=48,
                        topMargin=45, bottomMargin=60, title="ScamSignal APK Evaluation - 12 Public Applications",
                        author="ScamSignal", subject="Static APK evaluation, public sources and Arkiv verification")
doc.build(story, onFirstPage=page_chrome, onLaterPages=page_chrome)
for source in [pdf_path, csv_path, json_path]:
    shutil.copyfile(source, PUBLIC / source.name)
print(json.dumps({"outputs": [str(p) for p in [pdf_path, csv_path, json_path]], "samples": len(rows),
                  "arkiv_records": verification["verified_record_count"], "recorded_at": evaluation["evaluated_at"]}, indent=2))
