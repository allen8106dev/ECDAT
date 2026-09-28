# Advanced discovery and trust features

This remains a local scanner, not an authenticated multi-tenant service. No submitted code, build script, Git hook or container is executed. Full discovery of every cryptographic implementation in arbitrary binaries/languages is not guaranteed. Review the coverage section and warnings in each result.

## Git hosts and private repositories

Install Git on the backend host. The dashboard accepts HTTPS clone URLs from GitHub, GitLab, Bitbucket and self-hosted Git, plus GitHub `owner/repo` shorthand. For private HTTPS repositories set `ECDAT_GIT_TOKEN` and `ECDAT_GIT_TOKEN_HOST` to the exact hostname; the token is passed to Git in its environment, not in the URL, report or command line. Set `ECDAT_GIT_USERNAME` when the provider requires a specific Basic-auth username; the default is `x-access-token`. SSH is also available for providers using key-based authentication.

SSH URLs (`git@host:group/repository.git` or `ssh://git@host/group/repository.git`) require `ECDAT_ALLOWED_SSH_HOSTS`, an SSH key available to the backend process, and a verified `known_hosts` entry. Host-key checking is never disabled. Private network HTTPS/TLS hosts must appear in `ECDAT_ALLOWED_HOSTS` (comma-separated exact hostnames).

Git performs a shallow fetch into a temporary bare repository and produces a compressed archive. It never checks out or executes the target. No recursive submodules or Git LFS object downloads occur. Private submodules must be scanned separately. Network policies, repository permissions, unsupported Git server authentication, and resource limits can prevent a scan; these are errors or coverage limits rather than successful empty scans.

```powershell
python ecdat/cli.py https://github.com/owner/repository.git --kind git --ref main --output report.json
```

## Infrastructure discovery

Install optional Python clients:

```powershell
python -m pip install -r ecdat/requirements-integrations.txt
$env:ECDAT_ENABLE_INTEGRATIONS = '1'
```

Restart the API after setting environment variables. The dashboard's Infrastructure discovery form submits background jobs. CLI adapters are also available:

```powershell
python ecdat/cli.py example.org:443 --kind tls --output tls.json
python ecdat/cli.py registry.example.org/project/image:tag --kind image --output image.json
python ecdat/cli.py ap-south-1 --kind aws --output aws-keys.json
python ecdat/cli.py https://my-vault.vault.azure.net --kind azure --output azure-keys.json
python ecdat/cli.py projects/PROJECT/locations/LOCATION/keyRings/RING --kind gcp --output gcp-keys.json
```

- **TLS:** verifies hostname/certificate trust with the host trust store and inventories the negotiated protocol, cipher and leaf certificate. It does not enumerate every supported cipher, check revocation, or scan arbitrary ports automatically. Untrusted/expired endpoints fail verification explicitly.
- **Registry:** requires `skopeo` on PATH (typically a Linux/WSL scanner host). Configure registry credentials with `skopeo login`. Image content is copied into temporary storage, bounded, and scanned without running it. Whiteouts are applied to recognized Docker/OCI exports; links and unsupported nested indexes are flagged. Zstd layers are not supported.
- **AWS:** uses the standard boto3 credential chain and needs `kms:ListKeys` plus `kms:DescribeKey` in the selected region.
- **Azure:** uses `DefaultAzureCredential` and Key Vault key list/get permissions. It inventories key versions using public metadata; it never performs private-key operations.
- **GCP:** uses Application Default Credentials and KMS key/key-version list permissions for the selected key ring.

Cloud adapters read metadata only and never export private keys. They are scoped to the selected region/vault/key ring, not every account or subscription. SDK and credentials must be available on the backend host; do not paste credentials into target fields.

## Coverage and dependency relationships

Use the dashboard's **Large codebase** budget, or CLI `--scan-mode large`, for crypto-heavy repositories. Standard mode permits 20,000 findings / 20,000 entries / 120 seconds of inspection; Large permits 200,000 findings / 100,000 entries / 600 seconds. Both retain 512 MiB expanded-byte and per-file limits. Acquisition and report generation are additional time. Reaching a limit returns a partial report rather than a claim of complete coverage. The selected limits are recorded in each report.

Core syntax parsers cover Python, JavaScript, TypeScript, Java, C, C++, Go and Rust. Signatures remain the fallback for all other readable languages and files above the syntax-analysis size limit. Syntax parsing improves call identification but is not whole-program dataflow analysis.

Native syntax and executable parsers run in isolated worker processes with a five-second per-file deadline. Worker crashes or timeouts trigger signature fallback and an explicit coverage warning; they do not terminate the API. Syntax results are reused by remediation to avoid parsing each file twice.

LIEF inspects PE/ELF/Mach-O symbol/import/export tables. Visible strings are still inspected. A stripped, statically linked implementation may have no recognizable symbols or strings.

Python project metadata and Rust manifests/lockfiles are parsed structurally. npm lockfile v2/v3 dependencies are resolved against installation paths and displayed separately from file-to-crypto references. Unresolved package edges are reported. Other ecosystems do not yet have complete transitive resolution.

CBOM generation validates every output against the vendored official CycloneDX 1.6 schemas, offline. Software libraries, containers and crypto material use their respective schema categories. File-to-evidence relationships describe static references and should not be interpreted as runtime proof.

The dashboard loads a separate result view without the duplicate CBOM payload. Full JSON and CBOM exports stream as file downloads; history uses small cached summaries. This avoids loading the complete export into browser memory merely to display a scan. These cache files live below the configured scan-data directory.

## CAS history

Saved reports include an application CAS that gives each file/algorithm pair one vote, avoiding repeated-reference inflation. The existing per-evidence score remains available. The history panel charts the same source and risk profile; partial coverage and code changes can affect comparability. It reads the most recent 1,000 persisted reports and displays up to 20 trend points. Scores use transparent heuristic risk/migration weights, not independently measured readiness.

## Signed PDF and JSON exports

Click **Signed PDF + JSON bundle**. On first use the local backend creates an Ed25519 signing key in its ignored scan-data directory. Set `ECDAT_SIGNING_KEY` to use an administrator-managed PEM key instead. Restrict access to the key; Windows deployments should apply appropriate NTFS ACLs.

The ZIP contains the exact PDF/JSON bytes, a SHA-256 manifest, a detached Ed25519 signature and the signer's public key. This is a signed bundle, not an embedded PDF/PAdES signature. Pin the public key through an independently trusted channel: accepting a key merely because it came inside the ZIP does not establish identity. `/signing-key` exposes the configured public key and its fingerprint.

```powershell
python ecdat/operations.py keygen path/to/signer.pem
python ecdat/operations.py sign report.json --key path/to/signer.pem --output signed.zip
python ecdat/operations.py verify signed.zip --trusted-key path/to/signer.public.pem
```

## Reviewable GitHub pull requests

Set `ECDAT_GITHUB_TOKEN` with repository contents and pull-request permissions. Patches are re-generated against a pinned remote commit, require the original source fingerprint to match the scan, and are rejected if the base branch changes. Only supported hash replacements are generated; cipher/protocol/PQC migrations still require engineering review. Archive layouts other than the scanner's Git archive or GitHub-style ZIP may need a fresh repository scan.

```powershell
# Read-only preparation: prints diffs for review.
python ecdat/operations.py pull-request report.json --repository owner/repository --branch main
# Explicit publication: creates a new branch and a draft PR; never merges it.
python ecdat/operations.py pull-request report.json --repository owner/repository --branch main --publish
```

Publication is not part of scanning and is not automatically triggered from the dashboard. Failures after creating a branch may leave that branch for operator inspection.

## Optional public testnet anchoring

Configure `ECDAT_RPC_URL` and `ECDAT_ANCHOR_PRIVATE_KEY` for an operator-controlled funded testnet account. Only Polygon Amoy (80002) and Ethereum Sepolia (11155111) are allowed. An explicit transaction stores the CBOM SHA-256 digest as calldata; it does not upload source code or the report. Save the returned receipt. This adds an external reference to the local hash chain, not a guarantee that original findings were correct.

```powershell
python ecdat/operations.py anchor report.json --chain-id 80002 --publish --output receipt.json
python ecdat/operations.py verify-anchor report.json receipt.json
```

## Validation status

Automated tests exercise schema validation at 10,000 findings, syntax calls/aliases, native-worker recovery, real executable symbol inspection, DER certificate risk, container whiteouts, npm relationships, signatures/tampering, source fingerprint checks and mocked cloud clients. Public Git acquisition, TLS discovery and browser exports/history are smoke-tested. Cloud accounts, private-host authentication, registry acquisition and public blockchain transactions need environment-specific integration testing with real credentials/tools. The presence of an adapter is not evidence that those external services have been tested.

Implementation references: [CycloneDX 1.6 schemas](https://github.com/CycloneDX/specification/tree/1.6/schema), [Tree-sitter Python API](https://tree-sitter.github.io/py-tree-sitter/), [skopeo](https://github.com/containers/skopeo), [AWS KMS DescribeKey](https://docs.aws.amazon.com/boto3/latest/reference/services/kms/client/describe_key.html), [Azure Key Vault Keys](https://learn.microsoft.com/en-us/python/api/overview/azure/keyvault-keys-readme?view=azure-python), [Google Cloud KMS](https://docs.cloud.google.com/python/docs/reference/cloudkms/latest/google.cloud.kms_v1.services.key_management_service.KeyManagementServiceClient), [GitHub pull request API](https://docs.github.com/en/rest/pulls).
