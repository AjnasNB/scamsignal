"""Reproduce the five-app static evaluation; inputs remain private and untracked."""
from __future__ import annotations

import argparse
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .analysis import MAX_APK_BYTES, analyze_apk

SAMPLES = [
    {"id": "keepassdx", "name": "KeePassDX", "classification": "upstream-open-source-release", "release": "4.5.5 libre", "license": "GPL-3.0", "source_url": "https://github.com/Kunzisoft/KeePassDX/releases/tag/4.5.5", "license_url": "https://github.com/Kunzisoft/KeePassDX/blob/master/LICENSE", "download_url": "https://github.com/Kunzisoft/KeePassDX/releases/download/4.5.5/KeePassDX-4.5.5-libre.apk"},
    {"id": "aegis", "name": "Aegis", "classification": "upstream-open-source-release", "release": "3.4.3", "license": "GPL-3.0", "source_url": "https://github.com/beemdevelopment/Aegis/releases/tag/v3.4.3", "license_url": "https://github.com/beemdevelopment/Aegis/blob/master/LICENSE", "download_url": "https://github.com/beemdevelopment/Aegis/releases/download/v3.4.3/aegis-v3.4.3.apk"},
    {"id": "newpipe", "name": "NewPipe", "classification": "upstream-open-source-release", "release": "0.29.1", "license": "GPL-3.0", "source_url": "https://github.com/TeamNewPipe/NewPipe/releases/tag/v0.29.1", "license_url": "https://github.com/TeamNewPipe/NewPipe/blob/dev/LICENSE", "download_url": "https://github.com/TeamNewPipe/NewPipe/releases/download/v0.29.1/NewPipe_v0.29.1.apk"},
    {"id": "insecurebank", "name": "InsecureBankv2", "classification": "intentionally-insecure-training-app", "release": "repository commit 3c8cc3a", "license": "MIT", "source_url": "https://github.com/dineshshetty/Android-InsecureBankv2/tree/3c8cc3a3ce45ed56d0f58f236b541b41f992e51f", "license_url": "https://github.com/dineshshetty/Android-InsecureBankv2/blob/master/LICENSE", "download_url": "https://raw.githubusercontent.com/dineshshetty/Android-InsecureBankv2/3c8cc3a3ce45ed56d0f58f236b541b41f992e51f/InsecureBankv2.apk"},
    {"id": "pivaa", "name": "PIVAA", "classification": "intentionally-insecure-training-app", "release": "repository commit 7fde895", "license": "GPL-3.0", "source_url": "https://github.com/HTBridge/pivaa/tree/7fde8956083ec4c6023c75f013f72023d60eda12", "license_url": "https://github.com/HTBridge/pivaa/blob/master/LICENSE", "download_url": "https://raw.githubusercontent.com/HTBridge/pivaa/7fde8956083ec4c6023c75f013f72023d60eda12/apks/pivaa.apk"},
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--download", action="store_true", help="Download upstream samples into ignored .local/samples only.")
    parser.add_argument("--cached-reports", action="store_true", help="Assemble reports from an earlier measured run.")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    samples_dir = root / ".local" / "samples"
    results_dir = root / ".local" / "results"
    samples_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for sample in SAMPLES:
        apk_path = samples_dir / (sample["id"] + ".apk")
        if args.download:
            request = urllib.request.Request(sample["download_url"], headers={"User-Agent": "ScamSignal-static-evaluation"})
            with urllib.request.urlopen(request, timeout=45) as response, apk_path.open("wb") as output:
                count = 0
                while chunk := response.read(1024 * 1024):
                    count += len(chunk)
                    if count > MAX_APK_BYTES:
                        raise ValueError("Evaluation sample exceeds the supported size.")
                    output.write(chunk)
        report_path = results_dir / (sample["id"] + ".json")
        if args.cached_reports:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        else:
            report = analyze_apk(apk_path)
            report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        records.append({**sample, "ground_truth_note": "Upstream release provenance; not a guarantee of safety." if sample["classification"] == "upstream-open-source-release" else "Author describes this as an intentionally vulnerable training app. It is not classified as malware or a scam.", "report": report})
    evaluation = {
        "schema_version": 1,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "method": "Androguard 4.1.4 static manifest parsing + Android Build Tools 35.0.0 apksigner signature verification. APKs were not installed or executed.",
        "limitations": ["Five samples demonstrate integration behavior, not detection accuracy.", "Valid signatures establish identity, not publisher legitimacy or safety.", "Declared permissions are capabilities; grants, actual behavior, remote code, DEX behavior and signing lineage are not assessed.", "Two risky cases are purpose-built training apps, not real-world malicious APKs.", "APK binaries and embedded personal strings are excluded from this publication."],
        "samples": records,
    }
    (root / "scanner" / "evaluation.json").write_text(json.dumps(evaluation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (samples_dir / "manifest.json").write_text(json.dumps([{**s, "apk_sha256": r["report"]["apk_sha256"]} for s, r in zip(SAMPLES, records)], indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"samples": len(records), "signatures_verified": sum(s["report"]["signature"]["status"] == "verified" for s in records)}))


if __name__ == "__main__":
    main()
