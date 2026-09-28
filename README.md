# ECDAT — Unified cryptographic discovery

Scan an HTTPS Git repository (or configured SSH repository), drop a repository ZIP/TAR archive, or upload a source file, binary, JAR/WAR, or exported container image. The React dashboard submits background scan jobs to FastAPI, displays progress and searchable findings, and exports JSON reports and a schema-validated CycloneDX 1.6 CBOM. Each completed scan has an isolated ID and a hash-chained audit record.

## Run locally

Requires Python 3.12+ and Node.js 22.12+ (tested with Node.js 24.16).

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

- **Git repositories:** enter an HTTPS clone URL, `owner/repo` for GitHub, or a configured SSH clone URL. GitHub, GitLab, Bitbucket and self-hosted Git are supported through Git. Branches, tags and commit IDs are accepted. Private repositories require host-scoped backend credentials. Submodules and Git LFS objects are detected as coverage gaps and must be supplied separately.
- **Uploads:** drop files or a folder, use **Choose folder**, or browse for individual files. Folders and multiple files are packed into a TAR in the browser with their relative paths preserved, including Unicode and long names. The upload limit is 128 MiB including archive overhead and at most 20,000 entries. For larger folders, upload a compressed ZIP. ZIP/JAR/WAR and TAR/TAR.GZ/TGZ archives are inspected recursively in memory. Archive entries are never extracted to filesystem paths or executed.
- **Containers:** upload Docker-save or OCI archives. Recognized images are merged with whiteout and opaque-directory handling before scanning. Only the first image/platform is selected; links and unsupported layouts are reported as coverage gaps. Other nested archives retain recursive scanning. Registry acquisition uses optional `skopeo`; no target image or code is executed.
- **Dependency inventory:** ECDAT identifies crypto libraries declared in Python, Node.js, Go, Rust, Maven/Gradle and Docker manifests. It reports declared package versions where the manifest provides them; npm lockfile v2/v3 installation paths provide transitive dependency relationships. Other ecosystems provide manifest inventory only; vulnerability databases are not queried.
- **Risk context:** before a scan, set data lifetime, expected migration time, business criticality and a CRQC planning horizon. ECDAT applies Mosca's `X + Y > Z` assessment to quantum-vulnerable public-key findings and calculates a transparent 0–100 Crypto-Agility Score. These assumptions are included in the report and CBOM; they are planning inputs, not measured facts about the repository.
- **Results:** relative paths include `!/` for archive members. Text findings include line numbers; binary findings include byte offsets. PEM/DER certificates are parsed for public-key type/size, signature hash, validity period and expiry; PEM private keys are identified for key type/size without returning their contents. Search and priority filters are available, with paginated display and full report/CBOM downloads.

Text signatures run across readable files of any language. Tree-sitter adds call analysis for Python, JavaScript, TypeScript/TSX, Java, C, C++, Go and Rust, with Python import-alias resolution for supported calls. Files above 2 MiB and unsupported languages fall back to signatures; the dashboard reports analysis modes. Remediation is syntax-gated and review-only. Binary inspection combines strings with LIEF executable import/export/symbol analysis; it does not decompile arbitrary machine code. Hidden, obfuscated, stripped, encrypted or custom implementations can still be missed. Comments and unused code may produce signature evidence. Certificate/key risk follows recognized public-key algorithms; TLS discovery additionally verifies the negotiated connection using the host trust store.

See [Advanced discovery and trust features](docs/advanced-features.md) for cloud KMS, TLS, registry access, signed exports, CAS history, optional draft PRs and testnet anchoring.

## Performance and coverage limits

Compiled matching patterns and a two-worker background pool keep the UI responsive. Up to four jobs can be active/queued. Each scan is bounded by 20,000 visited files, 20,000 findings, 512 MiB cumulative expanded bytes, four archive levels and a 120-second cooperative inspection budget. Individual content inspection is limited to 32 MiB; archive members are limited to 128 MiB. The legacy GitHub archive endpoint has 128 MiB / 90-second limits. Git acquisition has a 512 MiB disk limit and a 120-second limit per Git operation. Registry acquisition has a 512 MiB / 120-second limit. These are prototype limits, not a hard process isolation boundary.

Select **Large codebase** in the dashboard (or CLI `--scan-mode large`) for up to 100,000 visited entries, 200,000 findings and 600 seconds of inspection. Byte, nesting and acquisition limits still apply. Native parsers run in isolated workers and fall back to signatures on failure; reports record the resulting coverage gaps. CycloneDX validation uses a cached compiled schema for large inventories.

`.git`, `.svn`, `node_modules`, `venv`, `.venv` and `__pycache__` directories are excluded. Symlinks, special files, encrypted ZIP entries and unsafe archive paths are skipped. **Any skipped content is reported as partial coverage**, including unreadable or corrupt archives. The first 200 warnings are included. No findings means no matching signatures in inspected content, not proof of no cryptography. Large image exports may need to be split or scanned with a purpose-built image analysis tool.

Uploaded/downloaded inputs are deleted after each job. Reports and the audit chain persist under `ecdat/scan-data/` (gitignored); set `ECDAT_DATA_DIR` to change this directory. Reports have no automatic expiry. The browser remembers its last scan ID, and completed reports survive server restarts. In-flight jobs do not survive restart. Run a **single Uvicorn worker process**, since job state and the background queue are process-local; audit writes use an operating-system file lock. The audit chain detects modification within stored records; it is not externally anchored tamper-proof storage.

The dashboard generates review-only diffs for unambiguous MD5/SHA-1 calls in Python, JavaScript/TypeScript, Java and OpenSSL C/C++ code. It never changes uploaded or GitHub code. Cipher migrations require design review and are deliberately not auto-patched.

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
| GET | `/scans/{id}/report.pdf` | Executive PDF with coverage, risk context and prioritized findings |
| GET | `/history` | Source-filtered scan history and application CAS |
| GET | `/scans/{id}/signed.zip` | Signed PDF/JSON bundle |
| GET | `/signing-key` | Public signing key and fingerprint |
| POST | `/scans/repository` | Generic Git import with URL and ref |
| POST | `/scans/discovery` | Opt-in TLS, registry or cloud KMS discovery |
| GET | `/audit/verify` | Verify the persisted audit chain |

Submission returns HTTP 202 and a job ID. Poll until `completed` or `failed`. API documentation is available at http://127.0.0.1:8000/docs. The old global `/cbom` and demo `/patches` routes have been replaced by per-job results; `POST /scan` now returns a background job.

## CLI and CI

Run a local directory scan with `python ecdat/cli.py path/to/project --output ecdat-report.json`. The command returns exit code `1` when high-priority findings exist, which makes it suitable for CI gates. The included GitHub Actions workflow validates ECDAT and uploads a scan report for each repository push and pull request.

## Validation

The dashboard includes a searchable priority heatmap and an interactive file-to-asset map. Counts are evidence records, not unique cryptographic assets. The map shows observed references, not inferred runtime dependencies. It displays up to 15 matching assets and 12 files per selected asset; search narrows the asset list, and clicking a file filters the full findings table.

The executive PDF includes up to 20 prioritized findings and 10 coverage warnings to keep large scans readable. Full JSON and CBOM downloads retain all scan results. PDF export requires the updated backend dependencies (`python -m pip install -r ecdat/requirements.txt`).

```powershell
python -m pip install -r ecdat/requirements-dev.txt
python -m unittest discover -s ecdat -p "test_*.py" -v
cd dashboard
npm.cmd run build
npm.cmd run lint
node --test src/*.test.mjs
```

Tests use temporary report storage and a local API subprocess. They cover cross-language discovery, archives and container layers, binary offsets, UTF-16 text, limits, unsafe paths, certificate/key metadata and key redaction, profile-driven Mosca/CAS results, HTTP uploads, job isolation, CBOM export and audit verification. No network is required for the automated suite.

Implementation references: [GitHub repository archive API](https://docs.github.com/en/rest/repos/contents#download-a-repository-archive-zip), [Python TAR archive security guidance](https://docs.python.org/3/library/tarfile.html#extraction-filters).
