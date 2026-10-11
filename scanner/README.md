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

The default local evaluator covers **seven inputs: five upstream releases and two training controls**. Run `python -m scanner.evaluate --download` to retrieve those pinned releases into ignored `.local/samples`, inspect them without execution, and write private reports plus `evaluation-reproduced.json` in `.local/results`. This command downloads the seven files on each invocation; upstream availability and local security controls can prevent retrieval. Without `--download`, it requires the APKs to be present already. It preserves the published twelve-input evaluation evidence. A signature verifier must be configured first; compare reproduced SHA-256 values with `evaluation.json` when checking the published artifacts. `--cached-reports` assembles existing private reports and performs no fresh APK analysis. To run the real API and integrity tests too, set `SCAMSIGNAL_INTEGRATION_APK` to a private local APK before running pytest; those tests otherwise skip.

For authorized malware research, install the separate optional packages with `python -m pip install -r scanner/requirements-research.txt`, then run `python -m scanner.research_evaluate --research-inputs --download`. This command attempts all twelve API uploads against the deployed demo by default; use `--api-url http://127.0.0.1:8000` for a running local service. It requires a reachable API with its signature verifier available. The opt-in operator command downloads only missing pinned inputs, retains the researchers' original password-protected archives in ignored storage, and decrypts selected malicious APKs in memory for bounded static uploads. It verifies primary research digests and published SHA-256 fingerprints before upload, checks bearer protection, and deletes each transient server report. The output remains private under `.local/results` and does not overwrite the published evidence. Without `--download`, all required local inputs must already exist. Upstream removals, local security controls, free-host quotas, or API timeouts can prevent a complete reproduction; do not disable security controls to force it. There is no consumer malware download or execution feature, and the research tooling is excluded from production deployment. The optional direct packages are pinned, but their complete transitive dependency graph is not locked; see [third-party notices](../NOTICE.md).

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

## Twelve-app evaluation

`evaluation.json` contains measured, sanitized results for five upstream open source releases, five historical malicious APKs with exact primary-research IOC matches, and two intentionally vulnerable training controls. The controls are **not confirmed malware or scams**. The malicious set spans three documented research families/campaigns: Exodus One, Android/Clipper.C, and three distinct Android/FakeApp.KP application packages. The malicious classification comes from the cited research; manifest heuristics do not independently establish it. Malicious binaries have no established redistribution licence, remain in the researchers' original encrypted archives, and are not distributed by this product. All APKs were static analysis inputs and were never installed or executed. The GPL applications are evaluation inputs only; their code and APK binaries are not incorporated into this MIT implementation.

`live-evaluation.json` records successful uploads of all twelve exact APKs to the deployed API, with signature verification, exact fingerprint agreement, session authorization, deletion, and frontend CORS checks. All twelve signatures verified. The fake BtcTurk specimen `com.app.elipticsoft.app` declares no permissions categorized as sensitive by this scanner, yet its exact MD5 appears in ESET's phishing research. This demonstrates why trusted external evidence adds information that manifest heuristics miss. A valid signature does not establish safety. This selected evaluation measures integration behavior, not malware detection accuracy.
