"""Dependency manifest and container metadata discovery without executing content."""
import json
import re
import tomllib
from pathlib import PurePosixPath


CRYPTO_LIBRARIES = {
    "cryptography": "Python cryptography", "pycryptodome": "PyCryptodome", "pycrypto": "PyCrypto",
    "bcrypt": "bcrypt", "argon2-cffi": "Argon2", "passlib": "Passlib", "openssl": "OpenSSL",
    "libssl": "OpenSSL", "libcrypto": "OpenSSL", "crypto-js": "crypto-js", "node-forge": "node-forge",
    "jose": "JOSE", "jsonwebtoken": "JSON Web Token", "bouncycastle": "Bouncy Castle",
    "bcprov-jdk": "Bouncy Castle", "libsodium": "libsodium", "ring": "Rust ring",
    "rustls": "rustls", "golang.org/x/crypto": "Go crypto extensions",
}
MANIFEST_NAMES = {"requirements.txt", "pyproject.toml", "package.json", "package-lock.json", "go.mod", "cargo.toml", "cargo.lock", "pom.xml", "build.gradle", "build.gradle.kts", "dockerfile", "manifest.json", "index.json", "oci-layout"}


def dependency_findings(name, text):
    leaf = PurePosixPath(name).name.lower()
    if leaf not in MANIFEST_NAMES:
        return []
    packages = _packages(leaf, text)
    findings = []
    for package, version, line in packages:
        normalized = package.lower().replace("_", "-")
        label = CRYPTO_LIBRARIES.get(normalized)
        if not label:
            continue
        evidence = f"{package}{' ' + version if version else ''}"
        findings.append({
            "file": name, "line": line, "offset": None, "pattern": label,
            "call": package, "evidence": evidence, "kind": "dependency",
            "confidence": "high", "severity": "review", "asset_type": "library",
            "recommendation": "Review this cryptographic library's version, support lifecycle, configuration and transitive dependencies.",
            "metadata": {"package": package, **({"version": version} if version else {}), "manifest": leaf},
        })
    if leaf in {"manifest.json", "index.json", "oci-layout"}:
        findings.append({
            "file": name, "line": 1, "offset": None, "pattern": "Container metadata",
            "call": leaf, "evidence": "Docker/OCI image manifest", "kind": "container",
            "confidence": "high", "severity": "info", "asset_type": "container",
            "recommendation": "Review image layers and the package inventory included in this exported container image.",
            "metadata": {"manifest": leaf},
        })
    return findings


def _packages(leaf, text):
    if leaf in {'pyproject.toml', 'cargo.toml', 'cargo.lock'}:
        try:
            data = tomllib.loads(text)
        except ValueError:
            return []
        if leaf == 'pyproject.toml':
            dependencies = list(data.get('project', {}).get('dependencies', []))
            for group in data.get('project', {}).get('optional-dependencies', {}).values():
                dependencies.extend(group)
            values = []
            for value in dependencies:
                match = re.match(r'([\w.-]+)(.*)', value)
                if match:
                    values.append((match[1], match[2], _line_for(text, value)))
            values.extend((name, str(value), _line_for(text, name)) for name, value in data.get('tool', {}).get('poetry', {}).get('dependencies', {}).items())
            return values
        if leaf == 'cargo.lock':
            return [(item['name'], item.get('version', ''), _line_for(text, 'name = "' + item['name'] + '"')) for item in data.get('package', [])]
        values = []
        for section in ('dependencies', 'dev-dependencies', 'build-dependencies'):
            for name, value in data.get(section, {}).items():
                values.append((name, value.get('version', '') if isinstance(value, dict) else str(value), _line_for(text, name)))
        return values
    if leaf in {"package.json", "package-lock.json"}:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []
        values = []
        if leaf == 'package-lock.json' and 'packages' in data:
            for location, entry in data['packages'].items():
                if not location:
                    continue
                package = entry.get('name') or location.rsplit('node_modules/', 1)[-1]
                values.append((package, entry.get('version', ''), _line_for(text, '"' + location + '"')))
            return values
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for package, version in data.get(section, {}).items():
                values.append((package, str(version), _line_for(text, f'"{package}"')))
        return values
    if leaf in {"requirements.txt", "pyproject.toml"}:
        return [(match.group(1), match.group(2) or "", _line_for(text, match.group(0))) for match in re.finditer(r"(?im)^\s*([a-z0-9_.-]+)\s*(?:[=~!<>]{1,2}\s*([^\s;,#]+))?", text)]
    if leaf == "go.mod":
        return [(match.group(1), match.group(2), _line_for(text, match.group(0))) for match in re.finditer(r"(?m)^\s*([^\s]+)\s+(v[^\s]+)", text) if match.group(1) != "module"]
    if leaf == "cargo.toml":
        return [(match.group(1), match.group(2) or "", _line_for(text, match.group(0))) for match in re.finditer(r"(?m)^\s*([a-zA-Z0-9_-]+)\s*=\s*[\"']?([^\"'\n}]*)", text)]
    if leaf == "pom.xml":
        return [(match.group(1), match.group(2) or "", _line_for(text, match.group(0))) for match in re.finditer(r"(?s)<artifactId>\s*([^<]+)\s*</artifactId>(?:.*?<version>\s*([^<]+)\s*</version>)?", text)]
    if leaf.startswith("build.gradle"):
        return [(match.group(2), match.group(3) or "", _line_for(text, match.group(0))) for match in re.finditer(r"[\"']([^:'\"]+):([^:'\"]+)(?::([^'\"]+))?[\"']", text)]
    if leaf == "dockerfile":
        return [(match.group(1), "", _line_for(text, match.group(0))) for match in re.finditer(r"(?i)\b(openssl|libssl|libcrypto|cryptography|libsodium)\b", text)]
    return []


def _line_for(text, needle):
    return text.count("\n", 0, text.find(needle)) + 1
