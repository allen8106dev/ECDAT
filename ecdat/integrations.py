"""Opt-in, metadata-only discovery adapters. Credentials stay on the scanner host."""
import os
import ipaddress
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
from scanner import Scanner, MAX_FINDINGS
from repository import public_host


def blank_report(findings, source, warnings=None):
    warnings = warnings or []
    return dict(findings=findings, patches=[], warnings=warnings, partial=bool(warnings),
                stats={'files_scanned': 0, 'files_skipped': 0, 'duration_seconds': 0}, coverage={source: len(findings)})


def managed_key(identifier, algorithm, provider, extra=None):
    size = re.search(r'RSA[_-](\d+)', algorithm, re.I)
    return dict(file=identifier, line=None, offset=None, pattern='Managed key', call=algorithm,
                evidence=f'{provider}: {algorithm}', kind='key-material', asset_type='key-material',
                severity='review', confidence='high', recommendation='Review key usage, rotation and post-quantum migration requirements.',
                metadata={'key_algorithm': algorithm, 'provider': provider, **({'key_size': int(size[1])} if size else {}), **(extra or {})})


def cloud_keys(provider, target):
    findings = []
    warnings = []
    started = time.monotonic()

    def add(item):
        if len(findings) >= MAX_FINDINGS or time.monotonic() - started > 120:
            raise TimeoutError('Cloud inventory limit reached; remaining keys were not inspected.')
        findings.append(item)

    try:
        if provider == 'aws':
            if not re.fullmatch(r'[a-z]{2}(?:-gov)?-[a-z]+-\d', target):
                raise ValueError('Enter an AWS region such as ap-south-1.')
            import boto3
            from botocore.config import Config
            client = boto3.client('kms', region_name=target, config=Config(connect_timeout=10, read_timeout=15, retries={'max_attempts': 2}))
            for page in client.get_paginator('list_keys').paginate():
                for item in page['Keys']:
                    key = client.describe_key(KeyId=item['KeyId'])['KeyMetadata']
                    add(managed_key(key['Arn'], key.get('KeySpec', 'unknown'), 'AWS KMS', {'usage': key.get('KeyUsage'), 'state': key.get('KeyState')}))
        elif provider == 'azure':
            parsed = urlsplit(target)
            if parsed.scheme != 'https' or not parsed.hostname or not parsed.hostname.endswith('.vault.azure.net') or parsed.username or parsed.port or parsed.path not in ('', '/') or parsed.query or parsed.fragment:
                raise ValueError('Enter an Azure vault URL: https://name.vault.azure.net')
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.keys import KeyClient
            with DefaultAzureCredential() as credential, KeyClient(vault_url=target, credential=credential, connection_timeout=10, read_timeout=15) as client:
                for prop in client.list_properties_of_keys():
                    for version in client.list_properties_of_key_versions(prop.name):
                        key = client.get_key(prop.name, version.version)
                        add(managed_key(key.id, str(key.key_type), 'Azure Key Vault', {'enabled': key.properties.enabled}))
        elif provider == 'gcp':
            if not re.fullmatch(r'projects/[\w-]+/locations/[\w-]+/keyRings/[\w-]+', target):
                raise ValueError('Enter projects/PROJECT/locations/LOCATION/keyRings/RING.')
            from google.cloud import kms
            client = kms.KeyManagementServiceClient()
            for key in client.list_crypto_keys(request={'parent': target}, timeout=20):
                for version in client.list_crypto_key_versions(request={'parent': key.name}, timeout=20):
                    add(managed_key(version.name, version.algorithm.name, 'Google Cloud KMS', {'state': version.state.name}))
        else:
            raise ValueError('Unknown cloud provider.')
    except ImportError as exc:
        raise ValueError('Install ecdat/requirements-integrations.txt to enable cloud adapters.') from exc
    except TimeoutError as exc:
        warnings.append(str(exc))
    return blank_report(findings, provider, warnings)


def tls_scan(target):
    parsed = urlsplit(target if '://' in target else 'https://' + target)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise ValueError('Enter a TLS hostname, optionally with a port.')
    host, port = parsed.hostname, parsed.port or 443
    if host not in os.environ.get('ECDAT_ALLOWED_HOSTS', '').split(','):
        public_host(host)
    # Resolve once and connect to this address, retaining hostname validation and SNI.
    address = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0][4]
    if host not in os.environ.get('ECDAT_ALLOWED_HOSTS', '').split(',') and not ipaddress.ip_address(address[0]).is_global:
        raise ValueError('TLS target resolved to a private address.')
    context = ssl.create_default_context()
    with socket.create_connection(address, timeout=10) as connection, context.wrap_socket(connection, server_hostname=host) as tls:
        certificate = tls.getpeercert(binary_form=True)
        protocol, cipher = tls.version(), tls.cipher()[0]
    scanner = Scanner()
    scanner.content(certificate, host + '.der')
    scanner.findings.append(dict(file=target, line=None, offset=None, pattern=protocol, call=cipher,
        evidence=f'{protocol}: {cipher}', kind='tls', asset_type='protocol', confidence='high', severity='review',
        recommendation='Review protocol policy and hybrid post-quantum key establishment.', metadata={'cipher': cipher, 'trust_verified': True}))
    return blank_report(scanner.findings, 'TLS', ['TLS scan checks the negotiated connection and leaf certificate, not every supported cipher or full certificate chain.'])


def image_scan(target):
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,400}', target):
        raise ValueError('Enter a container registry image reference, optionally pinned by digest.')
    if not shutil.which('skopeo'):
        raise ValueError('Install skopeo on the scanner host to copy registry images without executing them.')
    with tempfile.TemporaryDirectory(prefix='ecdat-image-') as directory:
        archive = Path(directory) / 'image.tar'
        process = subprocess.Popen(['skopeo', '--command-timeout', '120s', 'copy', 'docker://' + target, 'docker-archive:' + str(archive)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        start = time.monotonic()
        try:
            while process.poll() is None:
                if time.monotonic() - start > 125 or (archive.exists() and archive.stat().st_size > 512 * 1024 * 1024):
                    raise ValueError('Container acquisition limit reached (120 seconds / 512 MiB).')
                time.sleep(.2)
            if process.returncode:
                raise ValueError('Registry acquisition failed. Check the image reference and skopeo registry credentials.')
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
        report = Scanner().directory(directory)
        if 'merged container filesystem' not in report.get('coverage', {}):
            report['warnings'].append('Container final filesystem could not be reconstructed. Review coverage before interpreting results.')
            report['partial'] = True
        return report


def discover(kind, target):
    if kind == 'tls':
        return tls_scan(target)
    if kind == 'image':
        return image_scan(target)
    return cloud_keys(kind, target)
