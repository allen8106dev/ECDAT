import base64
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import socket
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, MagicMock
import zipfile

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cbom_builder import build_cbom
from container_layers import merged_files
from dependency_graph import dependency_graph
from dependency_scanner import dependency_findings
from github_pr import prepare_pr
from integrations import cloud_keys, managed_key
from remediation import generate_patch
from repository import repository_url
from risk_engine import assess_findings
from scanner import Scanner
from schema_validation import validate_cbom
from signing import generate_key, signed_bundle, verify_bundle
from source_analysis import syntax_calls


def tar_bytes(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        for path, content in files.items():
            info = tarfile.TarInfo(path); info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


class ExtendedTests(unittest.TestCase):
    def test_cbom_validates_all_asset_types(self):
        findings = [{'pattern': kind, 'file': 'a', 'asset_type': kind, 'line': 1} for kind in ('algorithm', 'certificate', 'key-material', 'library', 'container', 'protocol')]
        cbom = build_cbom(findings)
        validate_cbom(cbom)
        self.assertEqual(len(cbom['dependencies'][0]['dependsOn']), 6)
        self.assertEqual(cbom['components'][2]['cryptoProperties']['assetType'], 'related-crypto-material')
        self.assertNotIn('cryptoProperties', cbom['components'][3])

    def test_large_cbom_and_invalid_component_rejection(self):
        import fastjsonschema
        findings = [{'pattern': 'RSA', 'file': f'{i}.c', 'line': 1} for i in range(10000)]
        cbom = build_cbom(findings)
        self.assertEqual(len(cbom['components']), 20000)
        cbom['components'][0]['cryptoProperties']['assetType'] = 'library'
        with self.assertRaises(fastjsonschema.JsonSchemaValueException):
            validate_cbom(cbom)

    def test_ast_aliases_and_comments(self):
        scanner = Scanner()
        text = 'from hashlib import md5 as digest\n# hashlib.md5(fake)\nx = digest(b"ok")\nprint("hashlib.md5(fake)")\n'
        scanner.content(text.encode(), 'a.py')
        calls = [f for f in scanner.findings if f['kind'] == 'source-call']
        self.assertEqual([(f['pattern'], f['line']) for f in calls], [('MD5', 3)])
        self.assertIsNone(generate_patch('a.py', text))
        patch_data = generate_patch('b.py', '# hashlib.md5(x)\nx = hashlib.md5(b"ok")\n')
        self.assertTrue(any(line.startswith('+x = hashlib.sha256') for line in patch_data['diff']))
        self.assertFalse(any(line.startswith('-#') for line in patch_data['diff']))

    def test_parser_languages(self):
        for filename, text in [('a.js', 'crypto.createHash("md5")'), ('a.ts', 'crypto.createHash("md5")'), ('a.java', 'class A { void x() { MessageDigest.getInstance("MD5"); } }'), ('a.c', 'void f(){EVP_md5();}'), ('a.cpp', 'void f(){EVP_md5();}'), ('a.go', 'package main\nfunc main(){md5.New()}'), ('a.rs', 'fn main(){md5::compute("a");}')]:
            calls, mode = syntax_calls(filename, text)
            self.assertTrue(mode.startswith('syntax:'), (filename, mode))
            self.assertTrue(calls, filename)

    def test_der_certificate_and_risk(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test')])
        now = datetime.now(timezone.utc)
        certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(2).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256())
        scanner = Scanner(); scanner.content(certificate.public_bytes(serialization.Encoding.DER), 'test.der')
        findings, summary = assess_findings(scanner.findings)
        finding = next(f for f in findings if f['pattern'] == 'Certificate')
        self.assertTrue(finding['quantum_vulnerable'])
        self.assertEqual(finding['riskAssessment']['risk_score'], 10)
        self.assertGreater(summary['at_risk_now'], 0)

    def test_dependencies_and_graph(self):
        lock = {'packages': {'': {'dependencies': {'jose': '1'}}, 'node_modules/jose': {'version': '1', 'dependencies': {'crypto-js': '2'}}, 'node_modules/crypto-js': {'version': '2'}}}
        text = json.dumps(lock)
        self.assertEqual(len(dependency_findings('package-lock.json', text)), 2)
        graph = dependency_graph('package-lock.json', text)
        self.assertEqual(len(graph['edges']), 2)
        self.assertEqual(graph['unresolved'], [])
        findings = dependency_findings('pyproject.toml', '[project]\ndependencies = ["cryptography>=42"]')
        self.assertEqual(findings[0]['metadata']['package'], 'cryptography')

    def test_container_whiteouts(self):
        a = tar_bytes({'old.py': b'MD5', 'folder/old': b'DES', 'keep': b'SHA256'})
        b = tar_bytes({'.wh.old.py': b'', 'folder/.wh..wh..opq': b'', 'folder/new': b'AES'})
        image = tar_bytes({'manifest.json': json.dumps([{'Layers': ['a.tar', 'b.tar']}]).encode(), 'a.tar': a, 'b.tar': b})
        files, warnings = merged_files(image)
        self.assertEqual(files, {'keep': b'SHA256', 'folder/new': b'AES'})
        self.assertEqual(warnings, [])
        scanner = Scanner(); scanner.content(image, 'image.tar')
        self.assertNotIn('MD5', {f['pattern'] for f in scanner.findings})
        self.assertIn('merged container filesystem', scanner.coverage)

    def test_signatures_reject_tampering_and_wrong_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / 'signer.pem'; public = generate_key(key)
            bundle = signed_bundle({'findings': []}, key)
            self.assertTrue(verify_bundle(bundle, public))
            wrong = generate_key(Path(directory) / 'other.pem')
            with self.assertRaises(InvalidSignature):
                verify_bundle(bundle, wrong)
            output = io.BytesIO()
            with zipfile.ZipFile(io.BytesIO(bundle)) as source, zipfile.ZipFile(output, 'w') as target:
                for name in source.namelist():
                    target.writestr(name, b'changed' if name == 'report.pdf' else source.read(name))
            with self.assertRaises(ValueError):
                verify_bundle(output.getvalue(), public)

    def test_git_urls_reject_local_protocol_and_credentials(self):
        with patch('repository.public_host'):
            self.assertEqual(repository_url('owner/repo'), 'https://github.com/owner/repo')
            self.assertEqual(repository_url('https://gitlab.com/group/sub/repo.git'), 'https://gitlab.com/group/sub/repo.git')
        for url in ['file:///tmp/a', 'https://user:secret@example.org/repo', 'ssh://host/repo', 'https://example.org/repo?token=secret']:
            with self.assertRaises(ValueError):
                repository_url(url)
        with patch('socket.getaddrinfo', return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]):
            with self.assertRaises(ValueError):
                repository_url('https://localhost/repo')

    def test_aws_adapter_only_reads_metadata(self):
        client = MagicMock()
        client.get_paginator.return_value.paginate.return_value = [{'Keys': [{'KeyId': 'one'}]}, {'Keys': [{'KeyId': 'two'}]}]
        client.describe_key.side_effect = [{'KeyMetadata': {'Arn': 'arn:' + key, 'KeySpec': 'RSA_2048'}} for key in ('one', 'two')]
        modules = {'boto3': SimpleNamespace(client=lambda *a, **k: client), 'botocore': SimpleNamespace(), 'botocore.config': SimpleNamespace(Config=lambda **k: k)}
        with patch.dict(sys.modules, modules):
            report = cloud_keys('aws', 'ap-south-1')
        self.assertEqual(len(report['findings']), 2)
        findings, _ = assess_findings(report['findings'])
        self.assertTrue(all(f['quantum_vulnerable'] for f in findings))
        client.decrypt.assert_not_called(); client.get_public_key.assert_not_called()

    def test_pr_checks_source_fingerprint(self):
        original = 'import hashlib\nx=hashlib.md5(b"hi")\n'
        generated = generate_patch('code.py', original)
        def response(path, data=None):
            if '/git/trees/' in path:
                return {'tree': [{'path': 'code.py', 'type': 'blob', 'mode': '100755'}]}
            if '/commits/' in path:
                return {'sha': 'commit', 'commit': {'tree': {'sha': 'tree'}}}
            return {'encoding': 'base64', 'content': base64.b64encode(original.encode()).decode()}
        with patch('github_pr.github', side_effect=response):
            plan = prepare_pr({'patches': [generated]}, 'owner/repo', 'main')
            self.assertIn('hashlib.sha256', plan['files'][0]['content'])
            self.assertEqual(plan['files'][0]['mode'], '100755')
            generated['original_sha256'] = 'changed'
            with self.assertRaises(ValueError):
                prepare_pr({'patches': [generated]}, 'owner/repo', 'main')

    def test_azure_adapter_reads_versions(self):
        client = MagicMock()
        client.__enter__.return_value = client
        client.list_properties_of_keys.return_value = [SimpleNamespace(name='signing')]
        client.list_properties_of_key_versions.return_value = [SimpleNamespace(version='v1')]
        client.get_key.return_value = SimpleNamespace(id='vault/key/v1', key_type='EC', properties=SimpleNamespace(enabled=True))
        modules = {'azure': SimpleNamespace(), 'azure.identity': SimpleNamespace(DefaultAzureCredential=MagicMock()),
                   'azure.keyvault': SimpleNamespace(), 'azure.keyvault.keys': SimpleNamespace(KeyClient=lambda **kwargs: client)}
        with patch.dict(sys.modules, modules):
            report = cloud_keys('azure', 'https://example.vault.azure.net')
        findings, _ = assess_findings(report['findings'])
        self.assertTrue(findings[0]['quantum_vulnerable'])
        client.get_key.assert_called_once_with('signing', 'v1')

    def test_gcp_adapter_reads_versions(self):
        client = MagicMock()
        client.list_crypto_keys.return_value = [SimpleNamespace(name='key')]
        client.list_crypto_key_versions.return_value = [SimpleNamespace(name='key/versions/1', algorithm=SimpleNamespace(name='EC_SIGN_P256_SHA256'), state=SimpleNamespace(name='ENABLED'))]
        kms = SimpleNamespace(KeyManagementServiceClient=lambda: client)
        with patch.dict(sys.modules, {'google.cloud': SimpleNamespace(kms=kms), 'google.cloud.kms': kms}):
            report = cloud_keys('gcp', 'projects/project/locations/global/keyRings/ring')
        findings, _ = assess_findings(report['findings'])
        self.assertTrue(findings[0]['quantum_vulnerable'])

    def test_anchor_requires_matching_testnet(self):
        from audit_anchor import anchor_cbom
        web3 = MagicMock()
        web3.eth.chain_id = 1
        module = SimpleNamespace(Web3=MagicMock(return_value=web3))
        with patch.dict(sys.modules, {'web3': module}), patch.dict(os.environ, {'ECDAT_RPC_URL': 'https://rpc.example.org'}):
            with self.assertRaises(ValueError):
                anchor_cbom({}, 80002)
        web3.eth.send_raw_transaction.assert_not_called()

    def test_binary_symbol_table(self):
        from binary_analysis import _binary_symbols, symbol_findings
        from scanner import RULES
        fake = SimpleNamespace(imported_functions=[SimpleNamespace(name='EVP_md5')], exported_functions=[], symbols=[])
        with patch('lief.parse', return_value=fake):
            symbols, warning = _binary_symbols(b'MZ' + b'0' * 50)
        with patch('binary_analysis.binary_symbols', return_value=(symbols, warning)):
            findings, warning = symbol_findings(b'MZ' + b'0' * 50, 'app.exe', RULES)
        self.assertEqual(findings[0]['pattern'], 'MD5')
        self.assertEqual(findings[0]['kind'], 'binary-symbol')
        self.assertIsNone(warning)

    def test_actual_executable_symbols(self):
        from binary_analysis import binary_symbols
        symbols, warning = binary_symbols(Path(sys.executable).read_bytes())
        self.assertIsNone(warning)
        self.assertTrue(symbols)

    def test_native_parser_recovers_after_worker_exit(self):
        import native_worker
        calls, _ = syntax_calls('sample.py', 'hashlib.md5(b"test")')
        self.assertTrue(calls)
        worker = native_worker._local.worker
        worker.process.terminate()
        worker.process.join(timeout=3)
        calls, coverage = syntax_calls('sample.py', 'hashlib.md5(b"test")')
        self.assertEqual(calls, [])
        self.assertIn('failed or timed out', coverage)
        calls, coverage = syntax_calls('sample.py', 'hashlib.md5(b"test")')
        self.assertTrue(calls)
        self.assertEqual(coverage, 'syntax: python')

    def test_application_cas_deduplicates_repeated_references(self):
        a = {'file': 'a.py', 'pattern': 'RSA'}
        b = {'file': 'b.py', 'pattern': 'SHA256'}
        _, first = assess_findings([a, b]); _, second = assess_findings([a, a, a, b])
        self.assertEqual(first['application_crypto_agility_score'], second['application_crypto_agility_score'])

    def test_single_file_limit_preserves_partial_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sample.txt'
            path.write_text('MD5\nSHA1\nRSA\n', encoding='utf-8')
            with patch('scanner.MAX_FINDINGS', 1):
                report = Scanner().file(path)
        self.assertEqual(len(report['findings']), 1)
        self.assertTrue(report['partial'])
        self.assertIn('resource limit', report['warnings'][-1])

    def test_line_numbers_across_repeated_matches(self):
        scanner = Scanner()
        scanner.content(b'\nMD5 SHA1\n\nRSA\nSHA256\n', 'sample.txt')
        self.assertEqual([(f['pattern'], f['line']) for f in scanner.findings], [('MD5', 2), ('SHA1', 2), ('RSA', 4), ('SHA256', 5)])


if __name__ == '__main__':
    unittest.main()
