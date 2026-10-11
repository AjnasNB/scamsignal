from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import signal
import sys
import tempfile
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from .analysis import MAX_APK_BYTES, InvalidAPK, apksigner_command, validate_archive

REPORT_TTL_SECONDS = int(os.getenv("REPORT_TTL_SECONDS", "1800"))
SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "45"))
MAX_QUEUE_SIZE = int(os.getenv("MAX_QUEUE_SIZE", "6"))
ROOT = Path(__file__).resolve().parent.parent
TEMP = Path(os.getenv("SCAN_TEMP_DIR", str(Path(tempfile.gettempdir()) / "scamsignal-scans"))).resolve()


class BodyTooLarge(Exception):
    pass


class BodyLimitMiddleware:
    def __init__(self, app):
        self.app = app
        self.ingress = None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") != "POST":
            return await self.app(scope, receive, send)
        if self.ingress is None:
            self.ingress = asyncio.Semaphore(2)
        limit = MAX_APK_BYTES + 1024 * 1024
        headers = dict(scope.get("headers", []))
        if not headers.get(b"content-type", b"").lower().startswith(b"multipart/form-data;"):
            return await JSONResponse({"detail": "Upload a multipart APK file."}, status_code=415)(scope, receive, send)
        try:
            declared = int(headers.get(b"content-length", b"0"))
        except ValueError:
            declared = limit + 1
        if declared > limit:
            return await JSONResponse({"detail": "Upload body exceeds the 50 MB APK limit."}, status_code=413)(scope, receive, send)
        total = 0
        started = False

        async def bounded_receive():
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > limit:
                    raise BodyTooLarge()
            return message

        async def tracked_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            async with self.ingress:
                await self.app(scope, bounded_receive, tracked_send)
        except BodyTooLarge:
            if not started:
                await JSONResponse({"detail": "Upload body exceeds the 50 MB APK limit."}, status_code=413)(scope, receive, send)


@dataclass
class Job:
    token_hash: bytes
    path: Path
    status: str = "queued"
    report: dict | None = None
    error: str | None = None
    created: float = field(default_factory=time.monotonic)
    task: asyncio.Task | None = None


JOBS: dict[str, Job] = {}
SEM: asyncio.Semaphore | None = None


async def run_worker(job: Job) -> None:
    global SEM
    process = None
    try:
        assert SEM is not None
        async with SEM:
            job.status = "processing"
            process = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "scanner.cli", str(job.path),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                cwd=str(ROOT), env=os.environ.copy(),
                start_new_session=os.name != "nt",
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=SCAN_TIMEOUT_SECONDS)
            if process.returncode != 0:
                job.error = "This file could not be inspected. It may be malformed, unsupported, or exceed a resource limit."
                job.status = "failed"
            else:
                job.report = json.loads(stdout)
                job.status = "completed"
    except asyncio.TimeoutError:
        job.status = "failed"
        job.error = "Analysis exceeded its time limit. No safety conclusion was reached."
    except asyncio.CancelledError:
        raise
    except Exception:
        job.status = "failed"
        job.error = "Analysis could not complete. No safety conclusion was reached."
    finally:
        if process and process.returncode is None:
            if os.name != "nt":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            await process.wait()
        job.path.unlink(missing_ok=True)


async def janitor() -> None:
    while True:
        await asyncio.sleep(30)
        now = time.monotonic()
        for scan_id, job in list(JOBS.items()):
            if now - job.created > REPORT_TTL_SECONDS:
                if job.task and not job.task.done():
                    job.task.cancel()
                job.path.unlink(missing_ok=True)
                JOBS.pop(scan_id, None)
        # A crashed process can leave raw files. Startup and this sweep cover them.
        cutoff = time.time() - max(SCAN_TIMEOUT_SECONDS * 3, 180)
        for path in TEMP.glob("*.apk"):
            if path.stat().st_mtime < cutoff:
                path.unlink(missing_ok=True)


@asynccontextmanager
async def lifespan(app):
    global SEM
    TEMP.mkdir(parents=True, exist_ok=True)
    SEM = asyncio.Semaphore(int(os.getenv("SCAN_CONCURRENCY", "1")))
    # Job tokens are in memory, so old raw files after a restart cannot be resumed.
    for path in TEMP.glob("*.apk"):
        path.unlink(missing_ok=True)
    cleanup = asyncio.create_task(janitor())
    yield
    cleanup.cancel()
    tasks = [job.task for job in JOBS.values() if job.task and not job.task.done()]
    for task in tasks:
        task.cancel()
    await asyncio.gather(cleanup, *tasks, return_exceptions=True)
    for job in JOBS.values():
        job.path.unlink(missing_ok=True)
    JOBS.clear()


app = FastAPI(title="ScamSignal Scanner", version="1.0.0", lifespan=lifespan, docs_url=None, redoc_url=None)
app.add_middleware(BodyLimitMiddleware)
origins = [s.strip() for s in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if s.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False, allow_methods=["GET", "POST", "DELETE"], allow_headers=["Authorization", "Content-Type"])


def authorized_job(scan_id: str, authorization: str | None) -> Job:
    job = JOBS.get(scan_id)
    token = authorization[7:] if authorization and authorization.startswith("Bearer ") else ""
    if not job or not token or not hmac.compare_digest(job.token_hash, hashlib.sha256(token.encode()).digest()):
        raise HTTPException(status_code=404, detail="Scan not found or access token invalid.")
    if time.monotonic() - job.created > REPORT_TTL_SECONDS:
        raise HTTPException(status_code=410, detail="This temporary scan has expired.")
    return job


@app.get("/api/health")
async def health():
    return {"status": "ok", "schema_version": 1, "signature_verifier": "available" if apksigner_command() else "unavailable", "mode": "static-only", "max_apk_bytes": MAX_APK_BYTES}


@app.post("/api/scans", status_code=202)
async def create_scan(file: UploadFile = File(...)):
    # No client-supplied filename is stored, logged, or passed to a subprocess.
    if not (file.filename or "").lower().endswith(".apk"):
        await file.close()
        raise HTTPException(status_code=415, detail="Choose a single .apk file. Split APK bundles are not supported.")
    active = sum(job.status in ("queued", "processing") for job in JOBS.values())
    if active >= MAX_QUEUE_SIZE or len(JOBS) >= 200:
        await file.close()
        raise HTTPException(status_code=503, detail="The scanner is busy. Please try again shortly.")
    scan_id = secrets.token_urlsafe(18)
    token = secrets.token_urlsafe(32)
    TEMP.mkdir(parents=True, exist_ok=True)
    path = TEMP / (scan_id + ".apk")
    size = 0
    try:
        with path.open("xb") as handle:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_APK_BYTES:
                    raise HTTPException(status_code=413, detail="APK exceeds 50 MB.")
                handle.write(chunk)
        validate_archive(path)
    except HTTPException:
        path.unlink(missing_ok=True)
        raise
    except (InvalidAPK, OSError) as exc:
        path.unlink(missing_ok=True)
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        await file.close()
    job = Job(hashlib.sha256(token.encode()).digest(), path)
    JOBS[scan_id] = job
    job.task = asyncio.create_task(run_worker(job))
    return {"scan_id": scan_id, "access_token": token, "status": "queued", "expires_in_seconds": REPORT_TTL_SECONDS}


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str, authorization: str | None = Header(default=None)):
    job = authorized_job(scan_id, authorization)
    result = {"status": job.status}
    if job.report is not None:
        result["report"] = job.report
    if job.error:
        result["error"] = job.error
    return result


@app.delete("/api/scans/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, authorization: str | None = Header(default=None)):
    job = authorized_job(scan_id, authorization)
    if job.task and not job.task.done():
        job.task.cancel()
        await asyncio.gather(job.task, return_exceptions=True)
    job.path.unlink(missing_ok=True)
    JOBS.pop(scan_id, None)

