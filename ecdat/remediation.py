"""Conservative, review-only diffs for unambiguous legacy crypto calls."""
import difflib
import re
from pathlib import PurePosixPath


RULES = [
    ("Python MD5", {".py"}, re.compile(r"hashlib\.md5\s*\("), "hashlib.sha256("),
    ("Python SHA-1", {".py"}, re.compile(r"hashlib\.sha1\s*\("), "hashlib.sha256("),
    ("JavaScript MD5", {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}, re.compile(r"(createHash\(\s*['\"])md5(['\"]\s*\))", re.I), r"\1sha256\2"),
    ("JavaScript SHA-1", {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}, re.compile(r"(createHash\(\s*['\"])sha1(['\"]\s*\))", re.I), r"\1sha256\2"),
    ("Java MD5", {".java"}, re.compile(r"(MessageDigest\.getInstance\(\s*['\"])MD5(['\"]\s*\))"), r"\1SHA-256\2"),
    ("Java SHA-1", {".java"}, re.compile(r"(MessageDigest\.getInstance\(\s*['\"])SHA-1(['\"]\s*\))"), r"\1SHA-256\2"),
    ("OpenSSL EVP MD5", {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}, re.compile(r"\bEVP_md5\s*\(\s*\)"), "EVP_sha256()"),
    ("OpenSSL EVP SHA-1", {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}, re.compile(r"\bEVP_sha1\s*\(\s*\)"), "EVP_sha256()"),
]


def generate_patch(name, text):
    suffix = PurePosixPath(name).suffix.lower()
    patched = text
    changes = []
    for title, extensions, pattern, replacement in RULES:
        if suffix not in extensions:
            continue
        patched, count = pattern.subn(replacement, patched)
        if count:
            changes.append(f"{title}: {count} replacement{'s' if count != 1 else ''}")
    if not changes:
        return None
    diff = list(difflib.unified_diff(text.splitlines(), patched.splitlines(), fromfile=f"a/{name}", tofile=f"b/{name}", lineterm=""))
    return {"file": name, "changes": changes, "diff": diff, "review_required": True}
