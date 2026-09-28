"""ECDAT local API: isolated background scans with bounded input and persisted reports."""
import json
import hashlib
import os
import re
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse, quote
from urllib.request import Request as URLRequest, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, FileResponse
from pydantic import BaseModel, Field
from audit_chain import AuditChain
from cbom_builder import build_cbom
from scanner import Scanner
from risk_engine import assess_findings, normalize_profile

app = FastAPI(title='ECDAT Unified Scanner', version='2.0.0')
app.add_middleware(CORSMiddleware, allow_origins=['http://localhost:5173', 'http://127.0.0.1:5173'], allow_methods=['GET', 'POST'], allow_headers=['Content-Type'])
ROOT = Path(__file__).parent
DATA = Path(os.environ.get('ECDAT_DATA_DIR', str(ROOT / 'scan-data')))
DATA.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD = 128 * 1024 * 1024
POOL = ThreadPoolExecutor(max_workers=2)
SLOTS = threading.BoundedSemaphore(4)
LOCK = threading.RLock()
JOBS = {}

@contextmanager
def audit_lock():
    """Serialize audit access across threads and local backend processes."""
    with LOCK, (DATA / 'audit.lock').open('a+b') as handle:
        if handle.seek(0, 2) == 0:
            handle.write(b'0')
            handle.flush()
        started = time.monotonic()
        while True:
            try:
                handle.seek(0)
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() - started > 10:
                    raise TimeoutError('Audit storage is busy.')
                time.sleep(.05)
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == 'nt':
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

class GitHubInput(BaseModel):
    url: str = Field(max_length=500)
    ref: str = Field(default='', max_length=200)
    scan_mode: str = Field(default='standard', pattern='^(standard|large)$')
    data_lifetime_years: int = Field(default=10, ge=0, le=100)
    migration_time_years: int = Field(default=3, ge=0, le=100)
    criticality: int = Field(default=5, ge=1, le=10)
    crqc_arrival_years: int = Field(default=10, ge=0, le=100)

class DiscoveryInput(BaseModel):
    kind: str = Field(pattern='^(tls|image|aws|azure|gcp)$')
    target: str = Field(min_length=1, max_length=500)

@app.post('/scans/discovery', status_code=202)
def scan_discovery(body: DiscoveryInput):
    if os.environ.get('ECDAT_ENABLE_INTEGRATIONS') != '1':
        raise HTTPException(400, 'Set ECDAT_ENABLE_INTEGRATIONS=1 on the scanner host after configuring the required tools and credentials.')
    job = reserve(body.kind + ':' + body.target)
    POOL.submit(worker, job['id'], discovery=(body.kind, body.target))
    return job


def scan_profile(data_lifetime_years, migration_time_years, criticality, crqc_arrival_years):
    return normalize_profile({
        'data_lifetime_years': data_lifetime_years,
        'migration_time_years': migration_time_years,
        'criticality': criticality,
        'crqc_arrival_years': crqc_arrival_years,
    })

def github_archive(url, ref=''):
    parsed = urlparse(url.strip())
    parts = parsed.path.strip('/').split('/')
    if parsed.scheme != 'https' or parsed.netloc.lower() != 'github.com' or parsed.query or parsed.fragment or len(parts) != 2:
        raise ValueError('Enter a public repository URL: https://github.com/owner/repository. Use the separate branch field for a branch or tag.')
    owner, repo = parts
    repo = repo.removesuffix('.git')
    if not re.fullmatch(r'[A-Za-z0-9-]+', owner) or not re.fullmatch(r'[A-Za-z0-9_.-]+', repo) or repo in ('.', '..'):
        raise ValueError('Invalid GitHub repository name.')
    return f'https://api.github.com/repos/{owner}/{repo}/zipball' + ('/' + quote(ref, safe='') if ref else '')

class GitHubRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urlparse(newurl)
        if target.scheme != 'https' or target.netloc not in ('api.github.com', 'codeload.github.com'):
            raise ValueError('Unexpected archive download redirect.')
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def download(url, destination):
    opener = build_opener(GitHubRedirects())
    started, total = time.monotonic(), 0
    try:
        with opener.open(URLRequest(url, headers={'User-Agent': 'ECDAT-Scanner', 'Accept': 'application/vnd.github+json'}), timeout=20) as response, destination.open('wb') as out:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD or time.monotonic() - started > 90:
                    raise ValueError('Repository download exceeds the 128 MiB or 90 second limit.')
                out.write(chunk)
    except HTTPError as exc:
        raise ValueError(f'GitHub returned HTTP {exc.code}. Check that the repository/ref exists and is public; GitHub rate limits may also apply.') from exc
    except (URLError, TimeoutError) as exc:
        raise ValueError('Could not download from GitHub. Check network access and retry.') from exc

def atomic_json(path, value):
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    temporary.write_text(json.dumps(value, separators=(',', ':')), encoding='utf-8')
    temporary.replace(path)

def report_summary(report):
    summary = report.get('risk_summary') or {}
    return dict(id=report['id'], source=report['source'], timestamp=report.get('cbom', {}).get('metadata', {}).get('timestamp'),
                score=summary.get('application_crypto_agility_score'), profile=report.get('profile'), partial=report.get('partial', True),
                quantum_vulnerable=summary.get('quantum_vulnerable_assets'), findings=len(report.get('findings', [])), stats=report.get('stats', {}))

def cache_report(report):
    for folder in ('views', 'summaries'):
        (DATA / folder).mkdir(exist_ok=True)
    atomic_json(DATA / 'views' / f"{report['id']}.json", {key: value for key, value in report.items() if key != 'cbom'})
    atomic_json(DATA / 'summaries' / f"{report['id']}.json", report_summary(report))

def update(job_id, **values):
    with LOCK:
        JOBS[job_id].update(values)

def reserve(source, profile=None, scan_mode='standard'):
    if not SLOTS.acquire(blocking=False):
        raise HTTPException(429, 'Scanner is busy. Try again after a running scan completes.')
    job_id = uuid.uuid4().hex
    job = dict(id=job_id, source=source, status='queued', created_at=time.time(), stats={}, profile=profile or normalize_profile(), scan_mode=scan_mode)
    with LOCK:
        # Keep bounded job metadata; completed reports remain accessible on disk.
        if len(JOBS) >= 100:
            for old in list(JOBS):
                if JOBS[old]['status'] in ('completed', 'failed'):
                    del JOBS[old]
                    break
        JOBS[job_id] = job
    return dict(job)

def worker(job_id, directory=None, archive_url=None, temporary=None, repository=None, discovery=None):
    try:
        if archive_url:
            update(job_id, status='downloading')
            download(archive_url, Path(directory) / 'repository.zip')
        if repository:
            from repository import acquire_repository
            update(job_id, status='downloading')
            directory = acquire_repository(repository[0], repository[1], directory)
        update(job_id, status='scanning')
        if discovery:
            from integrations import discover
            report = discover(*discovery)
        else:
            report = Scanner(lambda stats: update(job_id, stats=stats), mode=JOBS[job_id]['scan_mode']).directory(directory)
        if report.get('warnings'):
            report['partial'] = True
        report['findings'], report['risk_summary'] = assess_findings(report['findings'], JOBS[job_id]['profile'])
        cbom = build_cbom(report['findings'])
        report.update(id=job_id, source=JOBS[job_id]['source'], profile=JOBS[job_id]['profile'], cbom=cbom)
        if repository:
            report['warnings'].append('Git submodules and Git LFS objects are not fetched. Upload them separately if needed.')
        try:
            with audit_lock():
                audit_path = DATA / 'audit.json'
                chain = AuditChain()
                if audit_path.exists():
                    chain.load_from_file(audit_path)
                    if not chain.verify_chain()[0]:
                        raise ValueError('Audit chain integrity check failed.')
                block = chain.add_scan_record(cbom)
                atomic_json(audit_path, chain.chain)
                report['audit_block_hash'] = block['hash']
        except (OSError, ValueError, KeyError, TypeError) as exc:
            report['audit_error'] = f'Scan results are available, but this scan could not be added to the audit chain. Existing audit data was preserved. {str(exc)[:160]}'
        atomic_json(DATA / f'{job_id}.json', report)
        cache_report(report)
        update(job_id, status='completed', stats=report['stats'], partial=report['partial'])
    except Exception as exc:
        update(job_id, status='failed', error=str(exc)[:500])
    finally:
        if temporary:
            temporary.cleanup()
        SLOTS.release()

@app.get('/')
def health():
    return {'status': 'ECDAT API running', 'version': '2.0.0'}

@app.post('/scans/repository', status_code=202)
def scan_repository(body: GitHubInput):
    from repository import repository_url
    try:
        url = repository_url(body.url)
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc)) from exc
    job = reserve(url, scan_profile(body.data_lifetime_years, body.migration_time_years, body.criticality, body.crqc_arrival_years), body.scan_mode)
    temporary = tempfile.TemporaryDirectory(prefix='ecdat-git-')
    POOL.submit(worker, job['id'], temporary.name, None, temporary, (url, body.ref))
    return job

@app.post('/scans/github', status_code=202)
def scan_github(body: GitHubInput):
    try:
        url = github_archive(body.url, body.ref)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    profile = scan_profile(body.data_lifetime_years, body.migration_time_years, body.criticality, body.crqc_arrival_years)
    job = reserve(body.url + (f' @ {body.ref}' if body.ref else ''), profile, body.scan_mode)
    temporary = tempfile.TemporaryDirectory(prefix='ecdat-')
    POOL.submit(worker, job['id'], temporary.name, url, temporary)
    return job

@app.post('/scans/upload', status_code=202)
async def scan_upload(
    request: Request,
    filename: str = 'upload.zip',
    scan_mode: str = Query('standard', pattern='^(standard|large)$'),
    data_lifetime_years: int = Query(10, ge=0, le=100),
    migration_time_years: int = Query(3, ge=0, le=100),
    criticality: int = Query(5, ge=1, le=10),
    crqc_arrival_years: int = Query(10, ge=0, le=100),
):
    if not filename or len(filename) > 200 or '/' in filename or '\\' in filename or not Scanner.safe_name(filename):
        raise HTTPException(400, 'Invalid filename.')
    job = reserve(filename, scan_profile(data_lifetime_years, migration_time_years, criticality, crqc_arrival_years), scan_mode)
    temporary = tempfile.TemporaryDirectory(prefix='ecdat-')
    try:
        total = 0
        with (Path(temporary.name) / filename).open('wb') as out:
            async for chunk in request.stream():
                total += len(chunk)
                if total > MAX_UPLOAD:
                    raise HTTPException(413, 'Upload exceeds 128 MiB.')
                out.write(chunk)
        if total == 0:
            raise HTTPException(400, 'The uploaded file is empty.')
        POOL.submit(worker, job['id'], temporary.name, None, temporary)
    except BaseException:
        temporary.cleanup()
        SLOTS.release()
        with LOCK:
            JOBS.pop(job['id'], None)
        raise
    return job

@app.post('/scan', status_code=202)
def demo(
    scan_mode: str = Query('standard', pattern='^(standard|large)$'),
    data_lifetime_years: int = Query(10, ge=0, le=100),
    migration_time_years: int = Query(3, ge=0, le=100),
    criticality: int = Query(5, ge=1, le=10),
    crqc_arrival_years: int = Query(10, ge=0, le=100),
):
    job = reserve('Bundled demonstration', scan_profile(data_lifetime_years, migration_time_years, criticality, crqc_arrival_years), scan_mode)
    POOL.submit(worker, job['id'], ROOT / 'demo-data')
    return job

def valid_id(job_id):
    if not re.fullmatch(r'[a-f0-9]{32}', job_id):
        raise HTTPException(404, 'Scan not found.')

@app.get('/scans/{job_id}')
def status(job_id: str):
    valid_id(job_id)
    with LOCK:
        if job_id in JOBS:
            return dict(JOBS[job_id])
    path = DATA / f'{job_id}.json'
    if path.exists():
        summary_path = DATA / 'summaries' / f'{job_id}.json'
        report = json.loads((summary_path if summary_path.exists() else path).read_text(encoding='utf-8'))
        return dict(id=job_id, status='completed', source=report['source'], stats=report['stats'], partial=report['partial'])
    raise HTTPException(404, 'Scan not found; an unfinished scan may have been interrupted by a server restart.')

@app.get('/history')
def history(source: str = '', limit: int = Query(50, ge=1, le=200)):
    entries = []
    paths = sorted((path for path in DATA.glob('*.json') if re.fullmatch(r'[a-f0-9]{32}', path.stem)), key=lambda path: path.stat().st_mtime, reverse=True)[:1000]
    for path in paths:
        try:
            summary_path = DATA / 'summaries' / path.name
            if summary_path.exists():
                summary = json.loads(summary_path.read_text(encoding='utf-8'))
            else:
                summary = report_summary(json.loads(path.read_text(encoding='utf-8')))
                summary_path.parent.mkdir(exist_ok=True)
                atomic_json(summary_path, summary)
            if source and summary.get('source') != source:
                continue
            entries.append(summary)
            if len(entries) >= limit:
                break
        except (OSError, ValueError, KeyError):
            continue
    return {'scans': entries, 'window': 'Most recent 1000 persisted reports; compare identical sources and profiles.'}

@app.get('/capabilities')
def capabilities():
    import shutil
    return {'git': bool(shutil.which('git')), 'registry': bool(shutil.which('skopeo')),
            'integrations_enabled': os.environ.get('ECDAT_ENABLE_INTEGRATIONS') == '1',
            'signed_exports': True}

@app.get('/scans/{job_id}/signed.zip')
def signed_export(job_id: str):
    from signing import signed_bundle, generate_key
    report = result(job_id)
    key_path = os.environ.get('ECDAT_SIGNING_KEY', str(DATA / 'signer.pem'))
    if not os.environ.get('ECDAT_SIGNING_KEY'):
        with audit_lock():
            if not Path(key_path).exists():
                generate_key(key_path)
    return Response(signed_bundle(report, key_path), media_type='application/zip', headers={
        'Content-Disposition': f'attachment; filename="ecdat-{job_id}-signed.zip"', 'Cache-Control': 'no-store'})

@app.get('/signing-key')
def signing_public_key():
    from cryptography.hazmat.primitives import serialization
    key_path = Path(os.environ.get('ECDAT_SIGNING_KEY', str(DATA / 'signer.pem')))
    if not key_path.exists():
        raise HTTPException(404, 'Export a signed report to initialize the local signing identity.')
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {'public_key_pem': public.decode(), 'sha256': hashlib.sha256(public).hexdigest(), 'trust': 'Pin this key through a trusted channel before verifying exported bundles.'}

@app.get('/scans/{job_id}/result')
def result(job_id: str, include_cbom: bool = True):
    valid_id(job_id)
    path = DATA / f'{job_id}.json'
    if not path.exists():
        raise HTTPException(404, 'Completed report not found.')
    if not include_cbom:
        view = DATA / 'views' / f'{job_id}.json'
        if not view.exists():
            cache_report(json.loads(path.read_text(encoding='utf-8')))
        return FileResponse(view, media_type='application/json')
    return json.loads(path.read_text(encoding='utf-8'))

@app.get('/scans/{job_id}/report.json')
def json_export(job_id: str):
    valid_id(job_id)
    path = DATA / f'{job_id}.json'
    if not path.exists():
        raise HTTPException(404, 'Completed report not found.')
    return FileResponse(path, media_type='application/json', filename=f'ecdat-{job_id}.json')

@app.get('/scans/{job_id}/cbom')
def cbom(job_id: str, download: bool = False):
    if not download:
        return result(job_id)['cbom']
    valid_id(job_id)
    path = DATA / 'cboms' / f'{job_id}.json'
    if not path.exists():
        document = result(job_id)['cbom']
        path.parent.mkdir(exist_ok=True)
        atomic_json(path, document)
    return FileResponse(path, media_type='application/json', filename=f'cbom-{job_id}.json')

@app.get('/scans/{job_id}/report.pdf')
def executive_report(job_id: str):
    from pdf_report import build_pdf
    report = result(job_id)
    return Response(build_pdf(report), media_type='application/pdf', headers={
        'Content-Disposition': f'attachment; filename="ecdat-{job_id}.pdf"',
        'Cache-Control': 'no-store',
    })

@app.get('/audit/verify')
def verify_audit():
    try:
        with audit_lock():
            chain = AuditChain()
            if (DATA / 'audit.json').exists():
                chain.load_from_file(DATA / 'audit.json')
            valid, index = chain.verify_chain()
            blocks = {block['hash']: block for block in chain.chain}
            report_errors = []
            reports_verified = 0
            for path in DATA.glob('*.json'):
                if path.name == 'audit.json':
                    continue
                report = json.loads(path.read_text(encoding='utf-8'))
                block_hash = report.get('audit_block_hash')
                if not block_hash:
                    continue
                block = blocks.get(block_hash)
                cbom = report.get('cbom')
                cbom_hash = hashlib.sha256(json.dumps(cbom, sort_keys=True).encode('utf-8')).hexdigest() if cbom else None
                if not block or block.get('cbom_hash') != cbom_hash:
                    report_errors.append(path.stem)
                else:
                    reports_verified += 1
            return dict(
                is_valid=valid and not report_errors,
                broken_index=index,
                records=len(chain.chain),
                reports_verified=reports_verified,
                report_errors=report_errors,
            )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return dict(is_valid=False, broken_index=None, error='Audit data could not be verified: ' + str(exc)[:160])
