import io
import json
import os
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from scanner import Scanner
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def zip_bytes(entries):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return out.getvalue()


class DiscoveryTests(unittest.TestCase):
    def scan(self, files):
        with tempfile.TemporaryDirectory() as directory:
            for name, data in files.items():
                path = Path(directory) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            return Scanner().directory(directory)

    def test_languages_nested_paths_and_modern_crypto(self):
        report = self.scan({'src/hash.js': b'crypto.createHash("md5")', 'java/hash.java': b'MessageDigest.getInstance("SHA-256")',
                            'go/hash.go': b'import "crypto/sha1"', 'rust/key.rs': b'RSA_new();', 'config/Dockerfile': b'RUN apk add openssl'})
        self.assertEqual({f['pattern'] for f in report['findings']}, {'MD5', 'SHA256', 'SHA1', 'RSA', 'OpenSSL'})
        self.assertEqual(report['stats']['files_scanned'], 5)
        self.assertTrue(all('/' in f['file'] for f in report['findings']))

    def test_binary_offsets(self):
        report = self.scan({'app.exe': b'MZ\x00\xffEVP_MD5\x00RSA_new'})
        md5 = next(f for f in report['findings'] if f['pattern'] == 'MD5')
        self.assertEqual(md5['offset'], 8)
        self.assertIsNone(md5['line'])
        self.assertEqual(md5['confidence'], 'low')

    def test_utf16_text(self):
        report = self.scan({'config.txt': 'AES\nSHA256'.encode('utf-16')})
        self.assertEqual([f['line'] for f in report['findings']], [1, 2])

    def test_dotnet_crypto_apis(self):
        report = self.scan({'Crypto.cs': b'new MD5CryptoServiceProvider(); new AesGcm(key); SHA256Managed.Create();'})
        self.assertEqual({f['pattern'] for f in report['findings']}, {'MD5', 'AES', 'SHA256'})

    def test_code_aware_calls_dependencies_and_patches(self):
        report = self.scan({
            'src/hash.py': b'import hashlib\nhashlib.md5(payload)\n',
            'requirements.txt': b'cryptography==44.0.0\npycryptodome>=3.20\n',
            'package.json': b'{"dependencies":{"crypto-js":"4.2.0"}}',
            'Dockerfile': b'FROM alpine\nRUN apk add openssl\n',
        })
        md5 = next(finding for finding in report['findings'] if finding['pattern'] == 'MD5')
        self.assertEqual(md5['kind'], 'source-call')
        self.assertEqual(md5['confidence'], 'high')
        dependencies = [finding for finding in report['findings'] if finding['kind'] == 'dependency']
        self.assertEqual({finding['metadata']['package'] for finding in dependencies}, {'cryptography', 'pycryptodome', 'crypto-js', 'openssl'})
        self.assertEqual(report['stats']['dependencies_found'], 4)
        self.assertEqual(report['patches'][0]['file'], 'src/hash.py')
        self.assertIn('hashlib.sha256(', '\n'.join(report['patches'][0]['diff']))

    def test_unsupported_compression_reports_partial(self):
        report = self.scan({'layer': b'\x28\xb5\x2f\xfdcompressed'})
        self.assertTrue(report['partial'])
        self.assertEqual(report['stats']['files_scanned'], 0)

    def test_token_boundaries_and_deduplication(self):
        report = self.scan({'code.txt': b'description roadside sha123 md5 md5\nmd5'})
        self.assertEqual([(f['pattern'], f['line']) for f in report['findings']], [('MD5', 1), ('MD5', 2)])

    def test_nested_container_tar_layer(self):
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode='w') as archive:
            member = tarfile.TarInfo('usr/lib/crypto.so'); content = b'\x7fELF\x00EVP_sha256'
            member.size = len(content); archive.addfile(member, io.BytesIO(content))
        report = self.scan({'container.zip': zip_bytes({'layer.tar': layer.getvalue()})})
        self.assertEqual(report['stats']['archives_opened'], 2)
        self.assertIn('container.zip!/layer.tar!/usr/lib/crypto.so', report['findings'][0]['file'])

    def test_oci_manifest_is_inventory_evidence(self):
        report = self.scan({'image.tar': zip_bytes({'manifest.json': b'[{"Config":"config.json","Layers":[]} ]'})})
        finding = next(finding for finding in report['findings'] if finding['pattern'] == 'Container metadata')
        self.assertEqual(finding['kind'], 'container')
        self.assertEqual(report['stats']['container_manifests_found'], 1)

    def test_unsafe_paths_and_exclusions(self):
        report = self.scan({'repo.zip': zip_bytes({'../escape': b'MD5', '/absolute': b'MD5', 'node_modules/dep.js': b'MD5', 'ok.py': b'SHA256'})})
        self.assertEqual(report['stats']['files_skipped'], 3)
        self.assertTrue(report['partial'])
        self.assertEqual([f['pattern'] for f in report['findings']], ['SHA256'])

    def test_tar_symlink_skipped(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w') as archive:
            member = tarfile.TarInfo('link'); member.type = tarfile.SYMTYPE; member.linkname = '/etc/passwd'; archive.addfile(member)
        report = self.scan({'image.tar': data.getvalue()})
        self.assertEqual(report['stats']['files_skipped'], 1)

    def test_corrupt_archive_reports_partial(self):
        report = self.scan({'bad.zip': b'PK\x03\x04invalid'})
        self.assertTrue(report['partial'])
        self.assertEqual(report['stats']['files_scanned'], 0)

    def test_limits_report_partial(self):
        with patch('scanner.MAX_FILE', 8):
            report = self.scan({'large.txt': b'AES ' * 5})
        self.assertTrue(report['partial'])
        self.assertEqual(report['findings'], [])
        with patch('scanner.MAX_FINDINGS', 1):
            report = self.scan({'code.txt': b'MD5\nSHA1\nAES'})
        self.assertTrue(report['partial'])
        self.assertEqual(len(report['findings']), 1)

    def test_private_key_not_exposed(self):
        report = self.scan({'key.pem': b'-----BEGIN PRIVATE KEY-----\nSECRETKEYDATA\n-----END PRIVATE KEY-----'})
        self.assertNotIn('SECRETKEYDATA', json.dumps(report))

    def test_certificate_and_private_key_metadata(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.test')])
        certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(1).not_valid_before(
            datetime.now(timezone.utc) - timedelta(days=1)).not_valid_after(datetime.now(timezone.utc) + timedelta(days=30)).sign(key, hashes.SHA256())
        pem = certificate.public_bytes(serialization.Encoding.PEM) + key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        report = self.scan({'certs/site.pem': pem})
        certificate_finding = next(finding for finding in report['findings'] if finding['pattern'] == 'Certificate')
        key_finding = next(finding for finding in report['findings'] if finding['pattern'] == 'Private key')
        self.assertEqual(certificate_finding['metadata']['public_key_size'], 2048)
        self.assertEqual(certificate_finding['metadata']['signature_algorithm'], 'sha256')
        self.assertEqual(key_finding['metadata']['key_size'], 2048)
        self.assertNotIn('PRIVATE KEY-----', certificate_finding['evidence'])


class APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        cls.base = f'http://127.0.0.1:{port}'
        cls.process = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'api:app', '--host', '127.0.0.1', '--port', str(port)],
            cwd=Path(__file__).parent, env={**os.environ, 'ECDAT_DATA_DIR': cls.directory.name}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                with urlopen(cls.base, timeout=1):
                    return
            except OSError:
                time.sleep(.1)
        cls.process.terminate(); cls.process.wait(); cls.directory.cleanup()
        raise RuntimeError('Test API failed to start')

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate(); cls.process.wait(timeout=10); cls.directory.cleanup()

    def request(self, path, data=None, content_type='application/octet-stream'):
        request = Request(self.base + path, data=data, headers={'Content-Type': content_type})
        with urlopen(request, timeout=10) as response:
            return json.load(response)

    def finish(self, job):
        for _ in range(100):
            current = self.request('/scans/' + job['id'])
            if current['status'] == 'completed':
                return self.request('/scans/' + job['id'] + '/result')
            self.assertNotEqual(current['status'], 'failed', current.get('error'))
            time.sleep(.05)
        self.fail('Scan did not finish')

    def test_upload_and_isolated_results_and_audit(self):
        a = self.request('/scans/upload?filename=repo.zip', zip_bytes({'src/index.js': b'createHash("md5")'}))
        b = self.request('/scans/upload?filename=modern.rs', b'SHA256')
        first, second = self.finish(a), self.finish(b)
        self.assertEqual([f['pattern'] for f in first['findings']], ['MD5'])
        self.assertEqual(first['patches'][0]['file'], 'repo.zip!/src/index.js')
        self.assertTrue(first['patches'][0]['review_required'])
        self.assertEqual([f['pattern'] for f in second['findings']], ['SHA256'])
        self.assertEqual(self.request('/scans/' + a['id'] + '/cbom'), first['cbom'])
        self.assertTrue(self.request('/audit/verify')['is_valid'])

    def test_profile_drives_mosca_risk_and_cbom(self):
        job = self.request('/scans/upload?filename=key.py&data_lifetime_years=15&migration_time_years=3&criticality=8&crqc_arrival_years=10', b'RSA_generate_key_ex')
        report = self.finish(job)
        finding = report['findings'][0]
        self.assertTrue(finding['quantum_vulnerable'])
        self.assertTrue(finding['riskAssessment']['at_risk_now'])
        self.assertEqual(report['risk_summary']['at_risk_now'], 1)
        self.assertEqual(report['profile']['criticality'], 8)
        properties = report['cbom']['components'][0]['properties']
        self.assertTrue(any(item['name'] == 'ecdat:riskAssessment' for item in properties))

    def test_empty_and_unsafe_upload_rejected(self):
        for path, body in [('/scans/upload?filename=empty', b''), ('/scans/upload?filename=../outside', b'AES')]:
            with self.assertRaises(HTTPError) as caught:
                self.request(path, body)
            self.assertEqual(caught.exception.code, 400)
            caught.exception.close()

    def test_non_github_urls_rejected(self):
        for url in ['http://github.com/a/b', 'https://localhost/repo', 'https://github.com.evil.test/a/b', 'https://github.com/a/b/tree/main']:
            with self.assertRaises(HTTPError) as caught:
                self.request('/scans/github', json.dumps({'url': url}).encode(), 'application/json')
            self.assertEqual(caught.exception.code, 400)
            caught.exception.close()

    def test_demo_and_missing_scan(self):
        report = self.finish(self.request('/scan', b''))
        self.assertGreater(report['stats']['files_scanned'], 0)
        self.assertIn('AES', {f['pattern'] for f in report['findings']})
        with self.assertRaises(HTTPError) as caught:
            self.request('/scans/' + '0' * 32)
        self.assertEqual(caught.exception.code, 404)
        caught.exception.close()

    def test_corrupt_audit_preserves_scan_results(self):
        audit = Path(self.directory.name) / 'audit.json'
        original = audit.read_bytes() if audit.exists() else b'[]'
        try:
            audit.write_bytes(b'[] broken audit data')
            report = self.finish(self.request('/scans/upload?filename=crypto.js', b'MD5'))
            self.assertEqual(report['findings'][0]['pattern'], 'MD5')
            self.assertIn('audit_error', report)
            self.assertFalse(self.request('/audit/verify')['is_valid'])
            self.assertEqual(audit.read_bytes(), b'[] broken audit data')
        finally:
            audit.write_bytes(original)

    def test_audit_verification_detects_changed_report(self):
        report = self.finish(self.request('/scans/upload?filename=crypto.js', b'MD5'))
        report_path = Path(self.directory.name) / f"{report['id']}.json"
        original = report_path.read_bytes()
        try:
            saved = json.loads(original)
            saved['cbom']['components'][0]['name'] = 'CHANGED'
            report_path.write_text(json.dumps(saved), encoding='utf-8')
            audit = self.request('/audit/verify')
            self.assertFalse(audit['is_valid'])
            self.assertIn(report['id'], audit['report_errors'])
        finally:
            report_path.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
