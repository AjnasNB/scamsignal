# ScamSignal APK scanner

This service performs static metadata inspection. APK contents are never installed, executed, or extracted onto the filesystem. It verifies APK signatures with Android `apksigner`, inspects the binary manifest with Androguard 4.1.4, and reports requested capabilities separately from observed behavior. DEX behavior and certificate rotation lineage are **not** assessed.

## Run locally

```powershell
python -m venv .local/venv
.local/venv/Scripts/python -m pip install -r scanner/requirements-dev.txt
$env:APKSIGNER_JAR = 'C:\path\to\android-sdk\build-tools\35.0.0\lib\apksigner.jar'
$env:CORS_ORIGINS = 'http://localhost:5173'
.local/venv/Scripts/python -m uvicorn scanner.api:app --host 127.0.0.1 --port 8000 --no-access-log
```

`requirements.lock.txt` records the complete tested production dependency resolution (with the Windows-only dependency marked explicitly). Install that file for a reproducible environment, then `pytest==9.1.1` and `httpx==0.28.1` if running tests. The shorter `requirements.txt` pins the top-level libraries for platform builds.

On Linux, install `apksigner` and a JRE or set `APKSIGNER_JAR` and optionally `JAVA_BIN` to private deployment paths. `JAVA_BIN` must name an executable, not a shell command. Run from the repository root. For Azure App Service use startup command `python -m uvicorn scanner.api:app --host 0.0.0.0 --port 8000 --no-access-log` and set the frontend's exact origin in `CORS_ORIGINS`.

Azure Oryx extracts application files into a temporary directory at runtime. A private vendored JRE can therefore use `APKSIGNER_JAR=.vendor/apksigner.jar` and `JAVA_BIN=.vendor/jre/bin/java`; both are resolved against the package root. Use `python -m scanner.startup` to restore the Java executable bit and start one uvicorn worker. The deployment bundle retains the JRE's licence files and is not part of the source repository.

CLI, requiring no running service:

```sh
python -m scanner.cli path/to/app.apk --output private-report.json
python -m pytest tests/scanner -q
```

Reproduce all five external-source reports with `python -m scanner.evaluate --download`. This downloads APKs exclusively to ignored `.local/samples`, inspects them without execution, writes private reports in `.local/results`, and publishes only sanitized metadata in `scanner/evaluation.json`. A signature verifier must be configured first. To run the real API and integrity tests too, set `SCAMSIGNAL_INTEGRATION_APK` to a private local APK before running pytest; those tests otherwise skip.

## API

- `POST /api/scans`: multipart field `file`, single `.apk` up to 50 MiB. Returns HTTP 202 with `scan_id`, `access_token`, `status`, `expires_in_seconds`.
- `GET /api/scans/{scan_id}`: `Authorization: Bearer <access_token>`. Returns `queued`, `processing`, `completed` plus `report`, or `failed` plus `error`.
- `DELETE /api/scans/{scan_id}`: same authorization. Cancels analysis and removes the temporary report.
- `GET /api/health`: static-only mode and verifier availability.

The report contract is `schema_version: 1`; manifest findings concern declared capabilities only. An Android-valid signing certificate establishes signing identity, not legitimacy or safety. No findings is never a safety certificate. An invalid signature and unavailable verifier are distinct states.

## Resource and privacy boundaries

Raw uploads use randomized names and are deleted after analysis, failure, cancellation, process restart, or a stale-file sweep. In-memory reports expire after 30 minutes; callers need a random session token whose digest alone is stored. The service intentionally has no Arkiv write capability; a private scan does not automatically become public. Uploaded filenames, certificate subjects, embedded strings, and exception traces do not appear in reports. Disable reverse-proxy request logging and avoid retaining request bodies.

Uploads are bounded before multipart parsing and during file copying. ZIP member count, expanded size, compression ratio, path traversal, encrypted members, and duplicate entries are checked. Worker concurrency defaults to one, queue to six, whole-analysis deadline to 45 seconds, and Java heap to 192 MB. No arbitrary upload is used as a command or executable.

Linux CLI workers also have a 25-second soft/30-second hard CPU limit. Cancellation or wall-time expiry terminates the process group, including a running Java verifier. Multipart ingress is limited to two concurrent readers; the deployment limits HTTP concurrency to 16.

These are process limits, **not a complete operating-system sandbox**. For a public production service, run the scanner under a dedicated non-root container with 768 MB memory and one CPU; restrict worker egress; configure platform authentication/rate limits and avoid co-hosting secrets. Azure free App Service does not provide per-job egress isolation. Metadata libraries remain a parser attack surface. The demo is intended for bounded static inspection, not malware execution.

## Five-app evaluation

`evaluation.json` contains measured, sanitized results for three upstream open source releases and two intentionally vulnerable training apps. The latter are **not confirmed malware or scams**. Binaries are kept outside the tracked repository, are not shipped with this service, and were not executed. Source links, licences, release hashes, exact findings, and limitations are included for reproducibility. The GPL applications are evaluation inputs only; their code and APK binaries are not incorporated into this MIT implementation.

`live-evaluation.json` records successful uploads of those five exact APKs to the deployed API, with signature verification, exact fingerprint agreement, session authorization, deletion, and frontend CORS checks. All five signatures verified; both insecure training apps also declared debugging and legacy target SDKs. A valid signature does not establish safety. This five-app sample measures integration behavior, not malware detection accuracy.
