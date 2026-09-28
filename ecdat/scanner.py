"""Bounded language-independent discovery; scanned content is never executed."""
import io
import os
import re
import stat
import tarfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from dependency_scanner import dependency_findings
from remediation import generate_patch
from source_analysis import syntax_calls
from binary_analysis import symbol_findings
from dependency_graph import dependency_graph
from container_layers import merged_files

RULES = [
 ('MD5', r'md5(?:CryptoServiceProvider)?', 'high', 'Avoid MD5 for security decisions; review use and migrate to SHA-256 or stronger.'),
 ('SHA1', r'sha[-_]?1(?:Managed|CryptoServiceProvider)?', 'high', 'Avoid SHA-1 for signatures and collision-sensitive uses.'),
 ('3DES', r'(?:3des|des3|tripledes|des-ede3)', 'high', 'Migrate triple DES to authenticated AES-GCM.'),
 ('DES', r'des', 'high', 'Replace DES with authenticated modern encryption.'),
 ('RC4', r'(?:rc4|arc4|arcfour)', 'high', 'Replace RC4 with AES-GCM or ChaCha20-Poly1305.'),
 ('RSA', r'rsa(?:encryption)?', 'review', 'Review key size, padding and purpose; plan post-quantum migration separately for encryption and signatures.'),
 ('ECDSA', r'ecdsa', 'review', 'Review curve and signature use; plan post-quantum signature migration.'),
 ('ECDH', r'ecdh', 'review', 'Review key exchange and post-quantum or hybrid migration.'),
 ('AES', r'aes(?:[-_]?(?:128|192|256)|Gcm|Ccm|Managed|CryptoServiceProvider)?', 'info', 'Confirm key handling, unique nonces and authenticated mode.'),
 ('SHA256', r'sha[-_]?256(?:Managed|CryptoServiceProvider)?', 'info', 'Modern hash detected; suitability depends on context.'),
 ('SHA384', r'sha[-_]?384', 'info', 'Modern hash detected; suitability depends on context.'),
 ('SHA512', r'sha[-_]?512', 'info', 'Modern hash detected; suitability depends on context.'),
 ('SHA3', r'sha3(?:[-_]?\d+)?', 'info', 'Modern hash detected; suitability depends on context.'),
 ('ChaCha20', r'chacha20(?:poly1305)?', 'info', 'Confirm authenticated encryption and unique nonces.'),
 ('Ed25519', r'ed25519', 'review', 'Modern classical signature; review post-quantum requirements.'),
 ('ML-KEM', r'(?:ml[-_]?kem(?:[-_]?\d+)?|kyber\d*)', 'info', 'Confirm standardized ML-KEM implementation and parameter set.'),
 ('ML-DSA', r'(?:ml[-_]?dsa(?:[-_]?\d+)?|dilithium\d*)', 'info', 'Confirm standardized ML-DSA implementation and parameter set.'),
 ('SLH-DSA', r'(?:slh[-_]?dsa|sphincs(?:plus)?)', 'info', 'Confirm standardized SLH-DSA implementation and parameter set.'),
 ('DSA', r'dsa', 'review', 'Plan a migration to ML-DSA or SLH-DSA signatures.'),
 ('DH', r'(?:diffie[-_]?hellman|dh)', 'review', 'Plan hybrid ML-KEM key establishment.'),
 ('bcrypt', r'bcrypt', 'info', 'Review password hashing work factor.'),
 ('scrypt', r'scrypt', 'info', 'Review password hashing memory and work factors.'),
 ('Argon2', r'argon2(?:id|i|d)?', 'info', 'Review password hashing parameters; prefer Argon2id.'),
 ('PBKDF2', r'pbkdf2(?:hmac)?', 'review', 'Review PRF, salt and iteration count.'),
 ('ECB', r'(?:mode[_-]ecb|aes/ecb|ecb)', 'high', 'ECB reveals patterns; use authenticated encryption where applicable.'),
 ('Private key', r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----', 'high', 'Review embedded private key material; remove and rotate if exposed.'),
 ('Certificate', r'-----BEGIN CERTIFICATE-----', 'info', 'Review certificate validity, algorithm and trust configuration.'),
 ('OpenSSL', r'(?:openssl|libcrypto|libssl)', 'review', 'Crypto library reference detected; review version and configuration.'),
]
SIGNATURE = re.compile(r'(?<![a-z0-9])(?:' + '|'.join(f'(?P<R{i}>{pattern})' for i, (_, pattern, _, _) in enumerate(RULES)) + r')(?![a-z0-9])', re.I)
RECOMMENDATIONS = {name: rec for name, _, _, rec in RULES}
EXCLUDED = {'.git', '.svn', '__pycache__', '.venv', 'venv', 'node_modules'}
MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_FILES = 20000
MAX_FINDINGS = 20000
MAX_SECONDS = 120
CERTIFICATE_BLOCK = re.compile(br"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----")
PRIVATE_KEY_BLOCK = re.compile(br"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
SOURCE_CALLS = [
    ("MD5", re.compile(r"\bhashlib\.md5\s*\(|\bcreateHash\s*\(\s*['\"]md5|\bMessageDigest\.getInstance\s*\(\s*['\"]MD5|\bEVP_md5\s*\(", re.I)),
    ("SHA1", re.compile(r"\bhashlib\.sha1\s*\(|\bcreateHash\s*\(\s*['\"]sha1|\bMessageDigest\.getInstance\s*\(\s*['\"]SHA-?1|\bEVP_sha1\s*\(", re.I)),
    ("DES", re.compile(r"\bDES\.new\s*\(|\bCipher\.getInstance\s*\(\s*['\"]DES|\bDES_set_key", re.I)),
    ("3DES", re.compile(r"\bDES3\.new\s*\(|\bCipher\.getInstance\s*\(\s*['\"](?:DESede|3DES)", re.I)),
    ("RC4", re.compile(r"\bARC4\.new\s*\(|\bCipher\.getInstance\s*\(\s*['\"]RC4", re.I)),
    ("RSA", re.compile(r"\bRSA\.generate\s*\(|\bRSA_generate_key|\bKeyPairGenerator\.getInstance\s*\(\s*['\"]RSA", re.I)),
    ("ECDSA", re.compile(r"\bECDSA\.(?:generate|sign)|\bSignature\.getInstance\s*\(\s*['\"](?:SHA\d*withECDSA|ECDSA)", re.I)),
]

class ScanLimit(ValueError):
    pass

class Scanner:
    def __init__(self, progress=None, mode='standard'):
        if mode not in {'standard', 'large'}:
            raise ValueError('Scan mode must be standard or large.')
        self.mode = mode
        self.max_findings = MAX_FINDINGS if mode == 'standard' else 200000
        self.max_files = MAX_FILES if mode == 'standard' else 100000
        self.max_seconds = MAX_SECONDS if mode == 'standard' else 600
        self.findings, self.warnings, self.patches = [], [], []
        self.stats = dict(files_scanned=0, files_skipped=0, archives_opened=0, bytes_scanned=0, text_files=0, binary_files=0)
        self.visited = self.expanded = 0
        self.started = time.monotonic()
        self.progress = progress or (lambda _: None)
        self.coverage = {}
        self.dependency_graphs = []

    def check(self):
        if time.monotonic() - self.started > self.max_seconds:
            raise ScanLimit('Scan time limit reached; coverage is partial.')
        if self.visited >= self.max_files or self.expanded >= MAX_TOTAL or len(self.findings) >= self.max_findings:
            raise ScanLimit('Scan resource limit reached; coverage is partial.')

    def skip(self, name, reason):
        self.stats['files_skipped'] += 1
        if len(self.warnings) < 200:
            self.warnings.append(f'{name}: {reason}')

    @staticmethod
    def safe_name(name):
        p = PurePosixPath(name.replace('\\', '/'))
        return not (p.is_absolute() or '..' in p.parts or ':' in name or '\x00' in name)

    def read_member(self, stream, size, name, depth):
        self.check()
        self.visited += 1
        if not self.safe_name(name):
            self.skip(name, 'unsafe path')
            return
        if any(p in EXCLUDED for p in PurePosixPath(name).parts):
            self.skip(name, 'excluded dependency/cache directory')
            return
        cap = min(MAX_TOTAL - self.expanded, 128 * 1024 * 1024)
        if size > cap:
            self.skip(name, 'member exceeds expansion limit')
            return
        data = stream.read(cap + 1)
        self.expanded += len(data)
        if len(data) > cap:
            raise ScanLimit('Expanded content limit reached; coverage is partial.')
        self.content(data, name, depth)

    def content(self, data, name, depth=0):
        self.check()
        if PurePosixPath(name).name == '.gitmodules':
            self.skip(name, 'Submodule configuration found; submodule repositories must be scanned separately.')
        if data.startswith(b'version https://git-lfs.github.com/spec/v1'):
            self.skip(name, 'Git LFS pointer found; upload the actual object to inspect it.')
            return
        if data.startswith((b'\x28\xb5\x2f\xfd', b'7z\xbc\xaf\x27\x1c', b'Rar!')):
            self.skip(name, 'unsupported compressed format (zstd, 7z or RAR); upload ZIP or TAR.GZ instead')
            return
        is_zip = data.startswith((b'PK\x03\x04', b'PK\x05\x06'))
        is_tar = data[257:262] == b'ustar' or data.startswith(b'\x1f\x8b') or name.lower().endswith(('.tar', '.tgz', '.tar.gz'))
        if is_zip or is_tar:
            if depth >= 4:
                self.skip(name, 'archive nesting limit')
                return
            self.stats['archives_opened'] += 1
            if is_tar and not is_zip:
                try:
                    merged = merged_files(data, max_bytes=max(0, MAX_TOTAL - self.expanded), max_entries=self.max_files - self.visited)
                    if merged is not None:
                        files, warnings = merged
                        for warning in warnings:
                            self.skip(name, warning)
                        self.coverage['merged container filesystem'] = self.coverage.get('merged container filesystem', 0) + 1
                        self.findings.append(dict(file=name, line=None, offset=None, pattern='Container metadata', call='image manifest', evidence='Merged container filesystem', kind='container', confidence='high', severity='info', asset_type='container', recommendation='Review final filesystem and separately audit historical image layers.'))
                        for path, payload in files.items():
                            self.read_member(io.BytesIO(payload), len(payload), name + '!/rootfs/' + path, depth + 1)
                        return
                except (ValueError, KeyError, TypeError, tarfile.TarError) as exc:
                    self.skip(name, 'Container merge unavailable: ' + str(exc)[:100])
                    return
            try:
                if is_zip:
                    with zipfile.ZipFile(io.BytesIO(data)) as archive:
                        for item in archive.infolist():
                            self.check()
                            if item.is_dir():
                                continue
                            child = f'{name}!/{item.filename}'
                            if not self.safe_name(item.filename) or stat.S_ISLNK(item.external_attr >> 16) or item.flag_bits & 1:
                                self.skip(child, 'unsafe path, link or encrypted entry')
                                continue
                            with archive.open(item) as stream:
                                self.read_member(stream, item.file_size, child, depth + 1)
                else:
                    with tarfile.open(fileobj=io.BytesIO(data), mode='r|*') as archive:
                        for item in archive:
                            self.check()
                            if item.isdir():
                                continue
                            child = f'{name}!/{item.name}'
                            if not item.isfile() or not self.safe_name(item.name):
                                self.skip(child, 'unsafe path, link or special file')
                                continue
                            with archive.extractfile(item) as stream:
                                self.read_member(stream, item.size, child, depth + 1)
            except (OSError, ValueError, EOFError, RuntimeError, tarfile.TarError, zipfile.BadZipFile) as exc:
                if isinstance(exc, ScanLimit):
                    raise
                self.skip(name, 'unreadable archive: ' + str(exc)[:160])
            return
        if len(data) > MAX_FILE:
            self.skip(name, 'file exceeds 32 MiB inspection limit')
            return
        binary = b'\x00' in data[:8192] and not data.startswith((b'\xff\xfe', b'\xfe\xff'))
        if binary:
            text = data.decode('latin1')  # Preserves byte offsets.
        else:
            try:
                text = data.decode('utf-16' if data.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig')
            except UnicodeDecodeError:
                binary = True
                text = data.decode('latin1')
        self.stats['files_scanned'] += 1
        self.stats['binary_files' if binary else 'text_files'] += 1
        self.stats['bytes_scanned'] += len(data)
        structured_patterns = self.crypto_metadata(data, name, binary)
        if binary:
            symbols, warning = symbol_findings(data, name, RULES)
            self.findings.extend(symbols[:max(0, self.max_findings - len(self.findings))])
            if warning:
                self.skip(name, warning)
        direct_matches = self.source_call_findings(name, text, binary)
        if not binary:
            patch = generate_patch(name, text, analysis=self._source_analysis)
            if patch:
                self.patches.append(patch)
        if not binary:
            try:
                self.findings.extend(dependency_findings(name, text)[:max(0, self.max_findings - len(self.findings))])
            except (ValueError, TypeError, AttributeError, KeyError):
                self.skip(name, 'Dependency manifest could not be parsed; signature scanning remains active.')
            graph = dependency_graph(name, text)
            if graph:
                self.dependency_graphs.append(graph)
        seen, line, previous = set(), 1, 0
        for match in SIGNATURE.finditer(text):
            self.check()
            algorithm, _, severity, recommendation = RULES[int(match.lastgroup[1:])]
            if algorithm in structured_patterns:
                continue
            if not binary:
                line += text.count('\n', previous, match.start())
                previous = match.start()
            location = match.start() if binary else line
            key = algorithm, location
            if key in seen or key in direct_matches:
                continue
            seen.add(key)
            self.findings.append(dict(file=name, line=None if binary else line, offset=match.start() if binary else None,
                pattern=algorithm, call=match.group(), evidence=match.group(), kind='binary' if binary else 'text',
                confidence='low' if binary else 'medium', severity=severity, recommendation=recommendation))
        self.progress(dict(self.stats))

    def source_call_findings(self, name, text, binary):
        if binary:
            return set()
        calls, coverage = syntax_calls(name, text)
        self._source_analysis = calls, coverage
        self.coverage[coverage] = self.coverage.get(coverage, 0) + 1
        if 'failed or timed out' in coverage or 'parser unavailable' in coverage:
            self.skip(name, coverage)
        matches = set()
        for call in calls:
            for algorithm, pattern in SOURCE_CALLS:
                match = pattern.search(call['resolved'])
                if not match or not re.fullmatch(r'[\w.\s]*', call['resolved'][:match.start()]):
                    continue
                self.check()
                line = call['line']
                key = (algorithm, line)
                if key in matches:
                    continue
                matches.add(key)
                severity = next(rule[2] for rule in RULES if rule[0] == algorithm)
                recommendation = RECOMMENDATIONS[algorithm]
                self.findings.append({
                    'file': name, 'line': line, 'offset': None, 'pattern': algorithm,
                    'call': match.group(), 'evidence': match.group(), 'kind': 'source-call',
                    'confidence': 'high', 'severity': severity, 'recommendation': recommendation,
                    'asset_type': 'algorithm', 'metadata': {'detection': coverage},
                })
        return matches

    def crypto_metadata(self, data, name, binary):
        structured_patterns = set()
        certificate_blocks = CERTIFICATE_BLOCK.findall(data)
        if not certificate_blocks and name.lower().endswith(('.cer', '.crt', '.der')):
            certificate_blocks = [data]
        for block in certificate_blocks:
            self.check()
            try:
                certificate = x509.load_pem_x509_certificate(block) if block.startswith(b'-----') else x509.load_der_x509_certificate(block)
                public_key = certificate.public_key()
                key_size = getattr(public_key, 'key_size', None)
                key_algorithm = public_key.__class__.__name__.replace('PublicKey', '')
                expires = certificate.not_valid_after_utc
                finding = self.structured_finding(
                    name, data, block, 'Certificate', 'certificate',
                    'high' if expires < datetime.now(timezone.utc) else 'info',
                    'Review certificate validity, signature algorithm, key size and trust configuration.',
                    {
                        'public_key_algorithm': key_algorithm,
                        **({'public_key_size': key_size} if key_size else {}),
                        'signature_algorithm': certificate.signature_hash_algorithm.name if certificate.signature_hash_algorithm else 'unknown',
                        'valid_from': certificate.not_valid_before_utc.isoformat(),
                        'valid_until': expires.isoformat(),
                        'expired': expires < datetime.now(timezone.utc),
                    },
                )
                self.findings.append(finding)
                structured_patterns.add('Certificate')
            except (ValueError, TypeError, UnsupportedAlgorithm):
                self.skip(name, 'certificate data could not be parsed')
        for block in PRIVATE_KEY_BLOCK.findall(data):
            self.check()
            try:
                key = serialization.load_pem_private_key(block, password=None)
                key_size = getattr(key, 'key_size', None)
                key_algorithm = key.__class__.__name__.replace('PrivateKey', '')
                self.findings.append(self.structured_finding(
                    name, data, block, 'Private key', 'key-material', 'high',
                    'Move private keys out of source or image layers, rotate exposed keys, and use managed secret storage.',
                    {'key_algorithm': key_algorithm, **({'key_size': key_size} if key_size else {}), 'encrypted': False},
                ))
                structured_patterns.add('Private key')
            except (ValueError, TypeError, UnsupportedAlgorithm):
                self.findings.append(self.structured_finding(
                    name, data, block, 'Private key', 'key-material', 'high',
                    'Review embedded private key material; remove and rotate if exposed.', {'encrypted_or_unreadable': True},
                ))
                structured_patterns.add('Private key')
        return structured_patterns

    @staticmethod
    def structured_finding(name, data, block, pattern, asset_type, severity, recommendation, metadata):
        offset = data.find(block)
        line = data[:offset].count(b'\n') + 1
        return {
            'file': name,
            'line': line,
            'offset': None,
            'pattern': pattern,
            'call': pattern,
            'evidence': f"{pattern}: " + ', '.join(f'{key.replace("_", " ")}={value}' for key, value in metadata.items() if key not in {'expired', 'encrypted'}),
            'kind': asset_type,
            'confidence': 'high',
            'severity': severity,
            'recommendation': recommendation,
            'asset_type': asset_type,
            'metadata': metadata,
        }

    def directory(self, root):
        root = Path(root)
        if not root.is_dir():
            raise ValueError('Scan directory does not exist')
        try:
            for parent, dirs, files in os.walk(root, followlinks=False):
                for directory in list(dirs):
                    if directory in EXCLUDED or (Path(parent) / directory).is_symlink():
                        dirs.remove(directory)
                        self.skip(str((Path(parent) / directory).relative_to(root)), 'excluded directory or link')
                for filename in sorted(files):
                    self.check()
                    path = Path(parent) / filename
                    name = path.relative_to(root).as_posix()
                    if path.is_symlink():
                        self.skip(name, 'symbolic link')
                        continue
                    try:
                        with path.open('rb') as stream:
                            self.read_member(stream, path.stat().st_size, name, 0)
                    except OSError:
                        self.skip(name, 'unreadable file')
        except ScanLimit as exc:
            self.skip('Scan', str(exc))
        return self.report()

    def file(self, path):
        path = Path(path)
        try:
            with path.open('rb') as stream:
                self.read_member(stream, path.stat().st_size, path.name, 0)
        except ScanLimit as exc:
            self.skip('Scan', str(exc))
        return self.report()

    def report(self):
        self.findings.sort(key=lambda f: (f['file'], f['line'] or 0, f['offset'] or 0, f['pattern']))
        dependency_count = sum(finding.get('kind') == 'dependency' for finding in self.findings)
        container_count = sum(finding.get('kind') == 'container' for finding in self.findings)
        return dict(findings=self.findings, patches=self.patches, stats={**self.stats, 'duration_seconds': round(time.monotonic() - self.started, 3), 'dependencies_found': dependency_count, 'container_manifests_found': container_count},
                    warnings=self.warnings, partial=bool(self.stats['files_skipped']), coverage=self.coverage, dependency_graphs=self.dependency_graphs,
                    limits={'mode': self.mode, 'files': self.max_files, 'findings': self.max_findings, 'seconds': self.max_seconds, 'expanded_bytes': MAX_TOTAL})

def scan_directory(path):
    return Scanner().directory(path)['findings']

def scan_file(filepath):
    return Scanner().file(filepath)['findings']
