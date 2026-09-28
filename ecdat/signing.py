"""Detached Ed25519 signatures over exported bytes; verification pins a trusted key."""
import base64
import hashlib
from io import BytesIO
import json
from pathlib import Path
import zipfile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pdf_report import build_pdf


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def generate_key(path):
    key = Ed25519PrivateKey.generate()
    with Path(path).open('xb') as output:
        output.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    Path(path).chmod(0o600)
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def signed_bundle(report, key_path):
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError('ECDAT_SIGNING_KEY must point to an Ed25519 PEM private key.')
    documents = {'report.json': canonical(report), 'report.pdf': build_pdf(report)}
    manifest = canonical({'algorithm': 'Ed25519', 'files': {name: hashlib.sha256(value).hexdigest() for name, value in documents.items()}})
    output = BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, content in documents.items():
            archive.writestr(name, content)
        archive.writestr('manifest.json', manifest)
        archive.writestr('manifest.sig', base64.b64encode(key.sign(manifest)))
        archive.writestr('signer.pem', key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return output.getvalue()


def verify_bundle(data, trusted_public_key):
    key = serialization.load_pem_public_key(trusted_public_key)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError('Expected a trusted Ed25519 public key.')
    with zipfile.ZipFile(BytesIO(data)) as archive:
        expected = {'report.json', 'report.pdf', 'manifest.json', 'manifest.sig', 'signer.pem'}
        limits = {'report.json': 512 * 1024 * 1024, 'report.pdf': 16 * 1024 * 1024, 'manifest.json': 65536, 'manifest.sig': 1024, 'signer.pem': 8192}
        if len(archive.infolist()) != 5 or set(archive.namelist()) != expected or any(i.file_size > limits[i.filename] for i in archive.infolist()):
            raise ValueError('Unexpected or oversized bundle contents.')
        manifest = archive.read('manifest.json')
        key.verify(base64.b64decode(archive.read('manifest.sig'), validate=True), manifest)
        hashes = json.loads(manifest)['files']
        if set(hashes) != {'report.json', 'report.pdf'}:
            raise ValueError('Incomplete signed manifest.')
        for name, digest in hashes.items():
            if hashlib.sha256(archive.read(name)).hexdigest() != digest:
                raise ValueError('Export content has been modified.')
    return True
