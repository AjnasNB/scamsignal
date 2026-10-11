"""Reproduce the twelve measured API uploads without executing or distributing APKs.

The research-input flag is an explicit operator opt-in. Only pinned, known-hash
specimens are accepted. Original encrypted archives remain in ignored storage;
individual malicious APKs are decrypted in memory and uploaded for static analysis.
This operator module is never exposed as a consumer download or execution feature.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pyzipper

MAX_BYTES = 50 * 1024 * 1024
COMMIT = "eef650faedacb06f11a778fb1e3a18bae4e5af36"
RESEARCH_INPUTS = {
    "exodus": ("Exodus.zip", "0f5f1409b1ebbee4aa837d20479732e11399d37f05b47b5359dc53a4001314e5.apk"),
    "clipper": ("clipper.zip", "clipper/86507924e47908aded888026991cd03959d1c1b171f32c8cc3ce62c4c45374ef.apk"),
    "faketurk": ("2FAStealer.zip", "3d955b203921ccb24888ccbdda536bba778694ab05cdf9fad088bd0f60bf8fc0.apk"),
    "faketurkbeta": ("2FAStealer.zip", "126547985987c3ecb1321a3a565d8565b64d437fd28418a6ba4bbc3220f684d2.apk"),
    "fakekoineks": ("2FAStealer.zip", "dbfab6e6fe3c2af3c8e23476b507eebed3cbe05633ab98fcb421ed156aa34236.apk"),
}


def download(url: str, destination: Path, maximum: int) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "ScamSignal-static-research"})
    temporary = destination.with_suffix(destination.suffix + ".partial")
    try:
        with urllib.request.urlopen(request, timeout=45) as response, temporary.open("wb") as output:
            count = 0
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > maximum:
                    raise ValueError("The research input exceeds its size bound.")
                output.write(chunk)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def input_bytes(sample: dict, folder: Path, allow_download: bool) -> bytes:
    if sample["classification"] == "documented-malware-sample":
        archive_name, member = RESEARCH_INPUTS[sample["id"]]
        quarantine = folder / "quarantine"
        quarantine.mkdir(parents=True, exist_ok=True)
        archive_path = quarantine / archive_name
        if not archive_path.exists() and allow_download:
            download(f"https://raw.githubusercontent.com/sk3ptre/AndroidMalware_2019/{COMMIT}/{archive_name}", archive_path, 20 * 1024 * 1024)
        with pyzipper.AESZipFile(archive_path) as archive:
            entries = archive.infolist()
            if len(entries) > 100:
                raise ValueError("The research archive has too many entries.")
            info = archive.getinfo(member)
            if not info.flag_bits & 1:
                raise ValueError("Expected an original password-protected specimen archive.")
            if info.file_size > MAX_BYTES or info.file_size / max(1, info.compress_size) > 180:
                raise ValueError("The research specimen exceeds its expansion bound.")
            data = archive.read(info, pwd=b"infected")
        evidence = sample["evidence_hash"]
        if hashlib.new(evidence["algorithm"], data).hexdigest() != evidence["value"]:
            raise ValueError("The specimen does not match the primary research IOC.")
    else:
        apk_path = folder / (sample["id"] + ".apk")
        if not apk_path.exists() and allow_download:
            download(sample["download_url"], apk_path, MAX_BYTES)
        if apk_path.stat().st_size > MAX_BYTES:
            raise ValueError("The release exceeds the upload size bound.")
        data = apk_path.read_bytes()
    if hashlib.sha256(data).hexdigest() != sample["report"]["apk_sha256"]:
        raise ValueError("The input differs from the measured release fingerprint.")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--research-inputs", action="store_true", help="Explicitly opt into the five historical malicious static-analysis inputs.")
    parser.add_argument("--download", action="store_true", help="Retrieve missing pinned evaluation inputs into ignored local storage only.")
    parser.add_argument("--api-url", default="https://scamsignal-api-20261011.azurewebsites.net")
    parser.add_argument("--output", type=Path, help="Default: .local/results/research-api-reproduced.json")
    args = parser.parse_args()
    if not args.research_inputs:
        parser.error("This operator evaluation requires explicit --research-inputs.")
    if not args.api_url.startswith("https://") and not args.api_url.startswith(("http://127.0.0.1:", "http://localhost:")):
        parser.error("Use an HTTPS API or a local loopback development API.")
    root = Path(__file__).resolve().parent.parent
    evaluation = json.loads((root / "scanner" / "evaluation.json").read_text(encoding="utf-8"))
    folder = root / ".local" / "samples"
    folder.mkdir(parents=True, exist_ok=True)
    records = []
    api = args.api_url.rstrip("/")
    with httpx.Client(timeout=90) as client:
        health = client.get(api + "/api/health")
        health.raise_for_status()
        if health.json()["signature_verifier"] != "available":
            raise RuntimeError("The API signature verifier is unavailable.")
        for sample in evaluation["samples"]:
            data = input_bytes(sample, folder, args.download)
            started = time.monotonic()
            response = client.post(api + "/api/scans", files={"file": ("evaluation.apk", data, "application/vnd.android.package-archive")})
            response.raise_for_status()
            job = response.json()
            endpoint = api + "/api/scans/" + job["scan_id"]
            headers = {"Authorization": "Bearer " + job["access_token"]}
            try:
                if client.get(endpoint).status_code != 404:
                    raise RuntimeError("Anonymous report access was accepted.")
                deadline = time.monotonic() + 70
                result = {}
                while time.monotonic() < deadline:
                    response = client.get(endpoint, headers=headers)
                    response.raise_for_status()
                    result = response.json()
                    if result["status"] in ("completed", "failed"):
                        break
                    time.sleep(0.5)
                if result.get("status") != "completed":
                    raise RuntimeError("The static evaluation did not complete.")
                report = result["report"]
                expected = sample["report"]
                if report["apk_sha256"] != expected["apk_sha256"] or report["package_name"] != expected["package_name"]:
                    raise RuntimeError("The API returned a different artifact identity.")
                if report["signature"]["status"] != "verified" or report["signature"]["signer_sha256"] != expected["signature"]["signer_sha256"]:
                    raise RuntimeError("The API signature differed from the measured reference.")
                records.append({"id": sample["id"], "classification": sample["classification"], "seconds": round(time.monotonic() - started, 2), "report": report})
                print(json.dumps({"id": sample["id"], "status": "passed", "signature": report["signature"]["status"]}), flush=True)
            finally:
                response = client.delete(endpoint, headers=headers)
                if response.status_code != 204 or client.get(endpoint, headers=headers).status_code != 404:
                    raise RuntimeError("The evaluation report could not be removed.")
                del data
    output = args.output or root / ".local" / "results" / "research-api-reproduced.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"tested_at": datetime.now(timezone.utc).isoformat(), "api_url": api, "method": "Static uploads only; no APK installation or execution; original encrypted research inputs; bearer reports deleted after verification.", "samples": records}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"samples_passed": len(records), "output": str(output)}))


if __name__ == "__main__":
    main()
