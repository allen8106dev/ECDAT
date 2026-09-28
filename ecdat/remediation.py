"""Conservative, review-only diffs for unambiguous legacy crypto calls."""
import difflib
import hashlib
import re
from pathlib import PurePosixPath
from source_analysis import syntax_calls


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


def generate_patch(name, text, analysis=None):
    suffix = PurePosixPath(name).suffix.lower()
    calls, coverage = analysis if analysis is not None else syntax_calls(name, text)
    if not coverage.startswith('syntax:'):
        return None
    source = text.encode('utf-8')
    replacements = {}
    changes = []
    for title, extensions, pattern, replacement in RULES:
        if suffix not in extensions:
            continue
        count = 0
        for call in calls:
            for match in pattern.finditer(call['text']):
                if not re.fullmatch(r'[\w.\s]*', call['text'][:match.start()]):
                    continue
                start = call['start'] + len(call['text'][:match.start()].encode('utf-8'))
                end = call['start'] + len(call['text'][:match.end()].encode('utf-8'))
                if (start, end) not in replacements:
                    replacements[start, end] = match.expand(replacement).encode('utf-8')
                    count += 1
        if count:
            changes.append(f'{title}: {count} replacements')
    if not changes:
        return None
    for (start, end), replacement in sorted(replacements.items(), reverse=True):
        source = source[:start] + replacement + source[end:]
    patched = source.decode('utf-8')
    diff = list(difflib.unified_diff(text.splitlines(), patched.splitlines(), fromfile=f"a/{name}", tofile=f"b/{name}", lineterm=""))
    return {"file": name, "changes": changes, "diff": diff, "review_required": True,
            'original_sha256': hashlib.sha256(text.encode()).hexdigest(),
            'patched_sha256': hashlib.sha256(patched.encode()).hexdigest()}
