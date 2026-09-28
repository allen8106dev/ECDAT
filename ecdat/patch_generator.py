"""
patch_generator.py - Generates unified diffs and automated code remediation patches.
"""

import difflib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Union

# Mapping of regex patterns to modernized replacements
SIMPLE_FIXES: Dict[str, str] = {
    r"hashlib\.md5\(": "hashlib.sha256(",
    r"from Crypto\.Cipher import DES": "from Crypto.Cipher import AES",
    r"Crypto\.Cipher\.DES\.new\(": "Crypto.Cipher.AES.new(",
    r"DES\.new\(": "AES.new(",
    r"Crypto\.Cipher\.DES\.MODE_ECB": "Crypto.Cipher.AES.MODE_GCM",
    r"DES\.MODE_ECB": "AES.MODE_GCM",
    r"Crypto\.Cipher\.DES\.block_size": "Crypto.Cipher.AES.block_size",
    r"DES\.block_size": "AES.block_size",
}


def generate_patch(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Reads a Python source file, applies regex fixes, and returns a patch dictionary.
    """
    path_obj = Path(file_path)
    original_content = path_obj.read_text(encoding="utf-8")
    patched_content = original_content
    changes_applied: List[str] = []

    for pattern, replacement in SIMPLE_FIXES.items():
        if re.search(pattern, patched_content):
            patched_content, count = re.subn(pattern, replacement, patched_content)
            if count > 0:
                changes_applied.append(
                    f"Replaced '{pattern}' with '{replacement}' ({count} occurrence{'s' if count > 1 else ''})"
                )

    # Compute unified diff
    diff_lines = list(
        difflib.unified_diff(
            original_content.splitlines(),
            patched_content.splitlines(),
            fromfile=f"a/{path_obj.name}",
            tofile=f"b/{path_obj.name}",
            lineterm="",
        )
    )
    diff_str = "\n".join(diff_lines)

    return {
        "file_path": str(path_obj),
        "file_name": path_obj.name,
        "original": original_content,
        "patched": patched_content,
        "changes": changes_applied,
        "diff": diff_str,
    }


def generate_all_patches(demo_dir: Union[str, Path] = "./demo-dir") -> List[Dict[str, Any]]:
    """
    Runs generate_patch() on every .py file in demo_dir, skipping files with no changes.
    """
    dir_path = Path(demo_dir)
    if not dir_path.exists():
        fallback = Path(__file__).parent / "demo-data"
        if fallback.exists():
            dir_path = fallback

    patch_results: List[Dict[str, Any]] = []

    for py_file in sorted(dir_path.glob("*.py")):
        result = generate_patch(py_file)
        if result["changes"]:
            patch_results.append(result)

    return patch_results


if __name__ == "__main__":
    demo_dir = "./demo-data"
    if not Path(demo_dir).exists():
        fallback = Path(__file__).parent / "demo-data"
        if fallback.exists():
            demo_dir = str(fallback)

    # 1. Generate patches for all vulnerable files capable of automated fixes
    patches = generate_all_patches(demo_dir)

    print("=" * 80)
    print("                    ECDAT Automated Patch Generator")
    print("=" * 80)
    print(f"Directory: {demo_dir}")
    print(f"Files remediated: {len(patches)}\n")

    for patch in patches:
        print(f"File: {patch['file_name']}")
        print("Changes applied:")
        for change in patch["changes"]:
            print(f"  - {change}")
        print("\nUnified Diff:")
        print(patch["diff"])
        print("-" * 80)

    # 2. Save patch results to patches_output.json
    output_file = Path(__file__).parent / "patches_output.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(patches, f, indent=2)

    print(f"\nSaved {len(patches)} patch result(s) to: {output_file.name}")

