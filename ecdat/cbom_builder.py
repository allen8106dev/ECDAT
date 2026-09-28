"""
cbom_builder.py - Converts cryptographic scan findings into CycloneDX 1.6-style CBOM JSON.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from scanner import scan_directory
from schema_validation import validate_cbom
import hashlib


def build_cbom(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Converts a list of scanner findings into a CycloneDX 1.6 CBOM document structure.
    """
    components: List[Dict[str, Any]] = []

    for finding in findings:
        asset_type = finding.get('asset_type', 'algorithm')
        component_type = asset_type if asset_type in {'library', 'container'} else 'cryptographic-asset'
        component = {
            "type": component_type,
            "bom-ref": 'evidence-' + str(len(components)),
            "name": finding.get("pattern", "UNKNOWN"),
            "cryptoProperties": {
                "assetType": 'related-crypto-material' if asset_type == 'key-material' else asset_type
            },
            "evidence": {
                "occurrences": [
                    {
                        "location": finding.get("file", ""),
                        **({"line": finding["line"]} if finding.get("line") else {})
                    }
                ]
            },
            "properties": [
                {
                    "name": "recommendation",
                    "value": finding.get("recommendation", "")
                }
            ] + [{"name": "ecdat:" + key, "value": json.dumps(finding[key], sort_keys=True) if isinstance(finding[key], (dict, list)) else str(finding[key])}
                 for key in ("kind", "confidence", "severity", "offset", "evidence", "classification", "quantum_vulnerable", "riskAssessment", "cryptoAgilityScore", "metadata")
                 if finding.get(key) is not None]
        }
        if component_type != 'cryptographic-asset':
            component.pop('cryptoProperties')
        components.append(component)

    file_refs = {}
    relationships = {}
    for finding, component in zip(findings, components):
        path = finding.get('file', '')
        ref = 'file-' + hashlib.sha256(path.encode()).hexdigest()
        file_refs[path] = ref
        relationships.setdefault(ref, []).append(component['bom-ref'])
    components.extend({'type': 'file', 'name': path, 'bom-ref': ref} for path, ref in file_refs.items())

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        },
        "components": components,
        "dependencies": [{"ref": ref, "dependsOn": links} for ref, links in relationships.items()]
    }

    return validate_cbom(cbom)


if __name__ == "__main__":
    target_dir = "./demo-data"
    if not Path(target_dir).exists():
        fallback = Path(__file__).parent / "demo-data"
        if fallback.exists():
            target_dir = str(fallback)

    # 1. Scan the target directory for findings
    findings = scan_directory(target_dir)

    # 2. Build CycloneDX 1.6 CBOM structure
    cbom_data = build_cbom(findings)

    # 3. Save to cbom_output.json in the project root
    output_path = Path(__file__).parent / "cbom_output.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(cbom_data, f, indent=2)

    # 4. Print summary to terminal
    num_components = len(cbom_data.get("components", []))
    print("=" * 60)
    print("                ECDAT CBOM Builder Summary")
    print("=" * 60)
    print(f"Components Found     : {num_components}")
    print(f"Output File Saved To : {output_path.name}")
    print(f"Absolute Path        : {output_path.resolve()}")
    print("Confirmation         : CBOM generated and saved successfully!")
    print("=" * 60)

