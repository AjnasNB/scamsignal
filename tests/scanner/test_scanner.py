import asyncio
import hashlib
import io
import os
import subprocess
import time
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from scanner import api
from scanner.analysis import InvalidAPK, permission_record, validate_archive, verify_signature


def zip_bytes(names=None):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in (names or [("AndroidManifest.xml", b"not-real-binary-xml")]):
            archive.writestr(name, value)
    return output.getvalue()


def test_invalid_archive_rejected(tmp_path):
    apk = tmp_path / "file.apk"
    apk.write_bytes(b"this is not an apk")
    with pytest.raises(InvalidAPK, match="readable APK"):
        validate_archive(apk)


@pytest.mark.parametrize("name", ["../escape", "/absolute", "C:/escape", "a/../../escape", "..\\escape"])
def test_zip_path_traversal_rejected(tmp_path, name):
    apk = tmp_path / "file.apk"
    apk.write_bytes(zip_bytes([("AndroidManifest.xml", b"xml"), (name, b"x")]))
    with pytest.raises(InvalidAPK, match="unsafe paths"):
        validate_archive(apk)


def test_compression_bomb_rejected(tmp_path):
    apk = tmp_path / "file.apk"
    apk.write_bytes(zip_bytes([("AndroidManifest.xml", b"xml"), ("padding", b"a" * 3_000_000)]))
    with pytest.raises(InvalidAPK, match="compression ratio"):
        validate_archive(apk)


def test_no_manifest_rejected(tmp_path):
    apk = tmp_path / "file.apk"
    apk.write_bytes(zip_bytes([("not-a-manifest", b"x")]))
    with pytest.raises(InvalidAPK, match="AndroidManifest"):
        validate_archive(apk)


def test_permission_description_does_not_assert_behavior():
    record = permission_record("android.permission.READ_SMS")
    assert record["category"] == "sensitive"
    assert record["description_en"].startswith("Requests")
    assert record["description_hi"]
    assert permission_record("example.permission.READ_SMS")["category"] == "standard"


def test_verifier_failure_is_invalid_not_verified(tmp_path, monkeypatch):
    monkeypatch.setattr("scanner.analysis.apksigner_command", lambda: ["test-verifier"])
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess([], 1, "Signer #1 certificate SHA-256 digest: " + "a" * 64, "DOES NOT VERIFY"))
    result = verify_signature(tmp_path / "any.apk")
    assert result["status"] == "invalid"
    assert result["signer_sha256"] == []


def test_verifier_extracts_only_fingerprints_and_verified_schemes(tmp_path, monkeypatch):
    monkeypatch.setattr("scanner.analysis.apksigner_command", lambda: ["test-verifier"])
    stdout = "Verified using v1 scheme (JAR signing): true\nVerified using v2 scheme (APK Signature Scheme v2): true\nSigner #1 certificate DN: private-subject\nSigner #1 certificate SHA-256 digest: " + "A" * 64
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess([], 0, stdout, ""))
    result = verify_signature(tmp_path / "any.apk")
    assert result["status"] == "verified"
    assert result["signer_sha256"] == ["a" * 64]
    assert result["schemes"] == ["v1", "v2"]
    assert "private-subject" not in str(result)


def test_verifier_unavailable_is_explicit(tmp_path, monkeypatch):
    monkeypatch.setattr("scanner.analysis.apksigner_command", lambda: None)
    assert verify_signature(tmp_path / "any.apk")["status"] == "unavailable"


def test_verifier_infrastructure_failure_is_not_invalid_apk(tmp_path, monkeypatch):
    monkeypatch.setattr("scanner.analysis.apksigner_command", lambda: ["test-verifier"])
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess([], 1, "", "UnsupportedClassVersionError: Java runtime"))
    assert verify_signature(tmp_path / "any.apk")["status"] == "unavailable"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "TEMP", tmp_path)
    async def worker(job):
        job.report = {"schema_version": 1, "apk_sha256": "a" * 64}
        job.status = "completed"
        job.path.unlink(missing_ok=True)
    monkeypatch.setattr(api, "run_worker", worker)
    with TestClient(api.app) as client:
        yield client


def test_upload_session_token_required_and_raw_deleted(client):
    result = client.post("/api/scans", files={"file": ("private-user-file.apk", zip_bytes(), "application/vnd.android.package-archive")})
    assert result.status_code == 202
    created = result.json()
    endpoint = "/api/scans/" + created["scan_id"]
    assert client.get(endpoint).status_code == 404
    assert client.get(endpoint, headers={"Authorization": "Bearer forged"}).status_code == 404
    headers = {"Authorization": "Bearer " + created["access_token"]}
    assert client.get(endpoint, headers=headers).json()["status"] == "completed"
    assert not list(api.TEMP.glob("*.apk"))
    assert client.delete(endpoint, headers=headers).status_code == 204
    assert client.get(endpoint, headers=headers).status_code == 404


def test_invalid_upload_rejected_without_retention(client):
    response = client.post("/api/scans", files={"file": ("fake.apk", b"not-an-apk")})
    assert response.status_code == 422
    assert not list(api.TEMP.glob("*.apk"))


def test_non_apk_rejected(client):
    assert client.post("/api/scans", files={"file": ("file.exe", zip_bytes())}).status_code == 415


def test_upload_body_limit_precedes_parsing(client):
    response = client.post("/api/scans", headers={"Content-Length": str(60 * 1024 * 1024), "Content-Type": "multipart/form-data; boundary=test"}, content=b"x")
    assert response.status_code == 413


def test_expired_report_not_returned(client):
    response = client.post("/api/scans", files={"file": ("app.apk", zip_bytes())}).json()
    job = api.JOBS[response["scan_id"]]
    job.created = time.monotonic() - api.REPORT_TTL_SECONDS - 1
    headers = {"Authorization": "Bearer " + response["access_token"]}
    assert client.get("/api/scans/" + response["scan_id"], headers=headers).status_code == 410


def test_queue_capacity_returns_retryable_error(client, monkeypatch):
    monkeypatch.setattr(api, "MAX_QUEUE_SIZE", 0)
    assert client.post("/api/scans", files={"file": ("app.apk", zip_bytes())}).status_code == 503


@pytest.mark.skipif(not os.getenv("SCAMSIGNAL_INTEGRATION_APK"), reason="Private, external APK fixture not configured")
def test_real_apk_signature_and_metadata():
    from scanner.analysis import analyze_apk
    report = analyze_apk(Path(os.environ["SCAMSIGNAL_INTEGRATION_APK"]))
    assert report["signature"]["status"] == "verified"
    assert report["signature"]["signer_sha256"]
    assert report["package_name"]
    assert report["coverage"]["dex"] is False
    assert report["apk_sha256"] == hashlib.sha256(Path(os.environ["SCAMSIGNAL_INTEGRATION_APK"]).read_bytes()).hexdigest()


@pytest.mark.skipif(not os.getenv("SCAMSIGNAL_INTEGRATION_APK"), reason="Private, external APK fixture not configured")
def test_real_api_upload_analysis_and_delete(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "TEMP", tmp_path)
    with TestClient(api.app) as client:
        source = Path(os.environ["SCAMSIGNAL_INTEGRATION_APK"])
        with source.open("rb") as input_file:
            response = client.post("/api/scans", files={"file": ("sample.apk", input_file, "application/vnd.android.package-archive")})
        assert response.status_code == 202
        created = response.json()
        endpoint = "/api/scans/" + created["scan_id"]
        headers = {"Authorization": "Bearer " + created["access_token"]}
        deadline = time.monotonic() + 50
        while time.monotonic() < deadline:
            result = client.get(endpoint, headers=headers).json()
            if result["status"] in ("completed", "failed"):
                break
            time.sleep(0.1)
        assert result["status"] == "completed", result
        assert result["report"]["signature"]["status"] == "verified"
        assert not list(tmp_path.glob("*.apk"))
        assert client.delete(endpoint, headers=headers).status_code == 204


@pytest.mark.skipif(not os.getenv("SCAMSIGNAL_INTEGRATION_APK"), reason="Private, external APK fixture not configured")
def test_real_signature_rejects_unsigned_archive_change(tmp_path):
    import shutil
    modified = tmp_path / "tampered.apk"
    shutil.copyfile(os.environ["SCAMSIGNAL_INTEGRATION_APK"], modified)
    # Add an inert ZIP member, never executable code, without re-signing the APK.
    with zipfile.ZipFile(modified, "a") as archive:
        archive.writestr("scamsignal-integrity-test.txt", "unsigned test change")
    validate_archive(modified)
    assert verify_signature(modified)["status"] == "invalid"
