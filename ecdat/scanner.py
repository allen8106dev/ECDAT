"""
scanner.py - AST-based cryptographic scanner for detecting vulnerable and legacy algorithms.
"""

import ast
import os
import re
from pathlib import Path
from typing import Any, Dict, List

# Target patterns (case-insensitive) and their post-quantum / modern recommendations
PATTERNS = ["md5", "sha1", "DES", "RSA", "ECDSA"]

RECOMMENDATIONS: Dict[str, str] = {
    "MD5": "MD5/SHA1 -> SHA-256 (MD5 is broken; migrate to SHA-256)",
    "SHA1": "MD5/SHA1 -> SHA-256 (SHA-1 is weak; migrate to SHA-256)",
    "DES": "DES -> AES-256 (DES 56-bit key is insecure; migrate to AES-256)",
    "RSA": "RSA -> ML-KEM (FIPS 203) (Classical RSA is vulnerable to Shor's algorithm)",
    "ECDSA": "ECDSA -> ML-DSA (FIPS 204) (Classical ECDSA is vulnerable to Shor's algorithm)",
}


def get_call_name(node: ast.AST) -> str:
    """Recursively extract the dotted function/attribute name from an AST call node."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        prefix = get_call_name(node.value)
        if prefix:
            return f"{prefix}.{node.attr}"
        return node.attr
    return ""


def match_pattern(call_name: str) -> str | None:
    """
    Check if the function call name contains any of the target patterns (case-insensitive).
    Splits by dots and underscores to match constituent algorithm tokens accurately.
    """
    tokens = re.split(r"[._]", call_name)
    tokens_upper = {token.upper() for token in tokens if token}

    for pattern in PATTERNS:
        if pattern.upper() in tokens_upper:
            return pattern.upper()
    return None


def scan_file(filepath: str | Path) -> List[Dict[str, Any]]:
    """Parse a single Python file using ast and return any cryptographic findings."""
    path_obj = Path(filepath)
    findings: List[Dict[str, Any]] = []

    try:
        source_code = path_obj.read_text(encoding="utf-8")
        tree = ast.parse(source_code, filename=str(path_obj))
    except Exception as exc:
        print(f"[-] Error parsing {path_obj.name}: {exc}")
        return findings

    # Walk the AST to inspect all function call nodes
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = get_call_name(node.func)
            if not call_name:
                continue

            matched = match_pattern(call_name)
            if matched:
                findings.append(
                    {
                        "file": path_obj.name,
                        "line": getattr(node, "lineno", 0),
                        "pattern": matched,
                        "call": call_name,
                        "recommendation": RECOMMENDATIONS.get(
                            matched, "Upgrade to modern standard"
                        ),
                    }
                )

    return findings


def scan_directory(path: str | Path) -> List[Dict[str, Any]]:
    """Scan all .py files in a folder and return a list of finding dictionaries."""
    dir_path = Path(path)
    all_findings: List[Dict[str, Any]] = []

    if not dir_path.is_dir():
        print(f"[-] Path is not a directory: {dir_path}")
        return all_findings

    # Scan all Python files in the directory
    py_files = sorted(dir_path.glob("*.py"))
    for py_file in py_files:
        file_findings = scan_file(py_file)
        all_findings.extend(file_findings)

    # Sort findings consistently by filename and line number
    all_findings.sort(key=lambda item: (item["file"], item["line"]))
    return all_findings


if __name__ == "__main__":
    target_directory = "./demo-data"

    # Fallback to local demo-data if running from outside the project directory
    if not Path(target_directory).exists():
        fallback = Path(__file__).parent / "demo-data"
        if fallback.exists():
            target_directory = str(fallback)

    print("=" * 80)
    print("                    ECDAT Cryptographic Algorithm Scanner")
    print("=" * 80)
    print(f"Scanning target directory: {target_directory}\n")

    findings = scan_directory(target_directory)

    if not findings:
        print("[+] No cryptographic vulnerabilities found.")
    else:
        print(f"Found {len(findings)} cryptographic finding(s):\n")
        for idx, finding in enumerate(findings, start=1):
            print(f"[{idx}] File           : {finding['file']} (line {finding['line']})")
            print(f"    Call Detected  : {finding['call']}")
            print(f"    Pattern Match  : {finding['pattern']}")
            print(f"    Recommendation : {finding['recommendation']}")
            print("-" * 80)

    print(f"\nScan completed. Total findings: {len(findings)}")

