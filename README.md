# ECDAT — Unified cryptographic discovery

Scan a public GitHub repository, drop a repository ZIP/TAR archive, or upload a source file, binary, JAR/WAR, or exported container image. The React dashboard submits background scan jobs to FastAPI, displays progress and searchable findings, and exports JSON reports and a CycloneDX-style CBOM. Each completed scan has an isolated ID and a hash-chained audit record.

## Run locally

Requires Python 3.10+ and Node.js 22.12+ (tested with Node.js 24.16).

From the repository root, in one terminal:

```powershell
python -m pip install -r ecdat/requirements.txt
python -m uvicorn api:app --app-dir ecdat --host 127.0.0.1 --port 8000
```

In a second terminal:

```powershell
cd dashboard
npm.cmd ci
npm.cmd run dev
```

Open **http://127.0.0.1:5173**. On macOS/Linux, use `npm` instead of `npm.cmd`. The development server proxies `/api` to port 8000. `VITE_API_URL` can override the API base URL for a separately hosted frontend; configure the backend CORS allowlist for that frontend's origin. This is a local application with no authentication or tenant separation. Do not expose its API publicly without adding those controls and deployment-level request limits.

If port 8000 is occupied, start Uvicorn with `--port 8001` and set `$env:ECDAT_API_TARGET = 'http://127.0.0.1:8001'` in the dashboard terminal before `npm.cmd run dev`. Restart an older running backend after updating this project.

## Inputs and results

- **GitHub:** enter `https://github.com/owner/repository`, optionally with a separate branch, tag or commit. The default branch is used if omitted. Public repositories only; private repositories can be downloaded by their owner and uploaded as an archive. GitHub rate limits and download errors are displayed. Submodules and Git LFS objects are not fetched.
- **Uploads:** drop files or a folder, use **Choose folder**, or browse for individual files. Folders and multiple files are packed into a TAR in the browser with their relative paths preserved, including Unicode and long names. The upload limit is 128 MiB including archive overhead and at most 20,000 entries. For larger folders, upload a compressed ZIP. ZIP/JAR/WAR and TAR/TAR.GZ/TGZ archives are inspected recursively in memory. Archive entries are never extracted to filesystem paths or executed.
- **Containers:** upload a Docker `save` or OCI archive, for example `docker save -o image.tar my-image:tag`. TAR layers and gzip-compressed layers are inspected recursively, including extensionless OCI blobs. Results include all stored layers, including files removed in later layers; this is not a reconstructed runtime filesystem. Registry pulls, running containers and zstd-compressed layers are not supported.
- **Risk context:** before a scan, set data lifetime, expected migration time, business criticality and a CRQC planning horizon. ECDAT applies Mosca's `X + Y > Z` assessment to quantum-vulnerable public-key findings and calculates a transparent 0–100 Crypto-Agility Score. These assumptions are included in the report and CBOM; they are planning inputs, not measured facts about the repository.
- **Results:** relative paths include `!/` for archive members. Text findings include line numbers; binary findings include byte offsets. PEM/DER certificates are parsed for public-key type/size, signature hash, validity period and expiry; PEM private keys are identified for key type/size without returning their contents. Search and priority filters are available, with paginated display and full report/CBOM downloads.

The matcher examines UTF-8/UTF-16 text without restricting source language or file extension. It detects 25 algorithm, key, certificate and library signature families, including modern algorithms. Binary detection searches visible byte strings, not machine instructions or decompiled code. Obfuscated, dynamically constructed, stripped, encrypted or custom crypto implementations can be missed. Comments, documentation, tests and unused library symbols can match. Confidence and priority indicate evidence to review, not a verified vulnerability or a clean security bill. Certificate validity is checked only from embedded certificate metadata; trust, revocation, host matching and live TLS are not validated.

## Performance and coverage limits

Compiled matching patterns and a two-worker background pool keep the UI responsive. Up to four jobs can be active/queued. Each scan is bounded by 20,000 visited files, 20,000 findings, 512 MiB cumulative expanded bytes, four archive levels and a 120-second cooperative inspection budget. Individual content inspection is limited to 32 MiB; archive members are limited to 128 MiB. Repository downloads have 128 MiB and 90-second limits. These are prototype limits, not a hard process isolation boundary.

`.git`, `.svn`, `node_modules`, `venv`, `.venv` and `__pycache__` directories are excluded. Symlinks, special files, encrypted ZIP entries and unsafe archive paths are skipped. **Any skipped content is reported as partial coverage**, including unreadable or corrupt archives. The first 200 warnings are included. No findings means no matching signatures in inspected content, not proof of no cryptography. Large image exports may need to be split or scanned with a purpose-built image analysis tool.

Uploaded/downloaded inputs are deleted after each job. Reports and the audit chain persist under `ecdat/scan-data/` (gitignored); set `ECDAT_DATA_DIR` to change this directory. Reports have no automatic expiry. The browser remembers its last scan ID, and completed reports survive server restarts. In-flight jobs do not survive restart. Run a **single Uvicorn worker process**, since the background queue and audit lock are process-local. The audit chain detects modification within stored records; it is not externally anchored tamper-proof storage.

The older `risk_engine.py` and `patch_generator.py` remain standalone demo utilities. The unified dashboard deliberately does not apply their hardcoded risk assumptions or automatic regex patches to uploaded repositories.

Audit writes use an operating-system file lock. If existing audit data is unreadable or invalid, it is preserved; scans still return their results with an explicit audit warning. Such scans have no verified audit record.

## API

| Method | Route | Purpose |
| --- | --- | --- |
| POST | `/scans/github` | JSON `{ "url": "https://github.com/owner/repo", "ref": "" }` |
| POST | `/scans/upload?filename=repo.zip` | Raw file bytes (`application/octet-stream`) |
| POST | `/scan` | Scan bundled demo data |
| GET | `/scans/{id}` | Job state and progress |
| GET | `/scans/{id}/result` | Completed findings and report |
| GET | `/scans/{id}/cbom` | Completed CBOM |
| GET | `/audit/verify` | Verify the persisted audit chain |

Submission returns HTTP 202 and a job ID. Poll until `completed` or `failed`. API documentation is available at http://127.0.0.1:8000/docs. The old global `/cbom` and demo `/patches` routes have been replaced by per-job results; `POST /scan` now returns a background job.

## Validation

```powershell
python -m unittest discover -s ecdat -p "test_*.py" -v
cd dashboard
npm.cmd run build
npm.cmd run lint
node --test src/uploads.test.mjs
```

Tests use temporary report storage and a local API subprocess. They cover cross-language discovery, archives and container layers, binary offsets, UTF-16 text, limits, unsafe paths, certificate/key metadata and key redaction, profile-driven Mosca/CAS results, HTTP uploads, job isolation, CBOM export and audit verification. No network is required for the automated suite.

Implementation references: [GitHub repository archive API](https://docs.github.com/en/rest/repos/contents#download-a-repository-archive-zip), [Python TAR archive security guidance](https://docs.python.org/3/library/tarfile.html#extraction-filters).
