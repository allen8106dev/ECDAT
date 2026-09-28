"""
cbom_builder.py - Converts cryptographic scan findings into CycloneDX 1.6-style CBOM JSON.
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from scanner import scan_directory


def build_cbom(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Converts a list of scanner findings into a CycloneDX 1.6 CBOM document structure.
    """
    components: List[Dict[str, Any]] = []

    for finding in findings:
        component = {
            "type": "cryptographic-asset",
            "name": finding.get("pattern", "UNKNOWN"),
            "cryptoProperties": {
                "assetType": finding.get("asset_type", "algorithm")
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
        components.append(component)

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        },
        "components": components
    }

    return cbom


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

