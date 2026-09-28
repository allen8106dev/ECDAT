"""
risk_engine.py - Mosca quantum risk theorem evaluation and Crypto Agility Score (CAS) enrichment.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Union

# Demo placeholder parameters for legacy and vulnerable cryptographic algorithms
DEMO_PARAMS: Dict[str, Dict[str, int]] = {
    "RSA": {"data_lifetime": 15, "migration_time": 3, "criticality": 9, "migration_effort": 7},
    "ECDSA": {"data_lifetime": 15, "migration_time": 3, "criticality": 8, "migration_effort": 6},
    "MD5": {"data_lifetime": 5, "migration_time": 1, "criticality": 5, "migration_effort": 2},
    "SHA1": {"data_lifetime": 5, "migration_time": 1, "criticality": 5, "migration_effort": 2},
    "DES": {"data_lifetime": 10, "migration_time": 2, "criticality": 7, "migration_effort": 4},
}


def mosca_risk(data_lifetime_years, migration_time_years, crqc_arrival_years=10):
    total_exposure = data_lifetime_years + migration_time_years
    at_risk = total_exposure > crqc_arrival_years
    return {
        "X_data_lifetime": data_lifetime_years,
        "Y_migration_time": migration_time_years,
        "Z_crqc_estimate": crqc_arrival_years,
        "at_risk_now": at_risk,
        "urgency_score": round(total_exposure / crqc_arrival_years, 2)
    }


def crypto_agility_score(risk_score, criticality_weight, migration_effort):
    raw_penalty = (risk_score * 0.5) + (criticality_weight * 0.3) + (migration_effort * 0.2)
    readiness = max(0, 100 - (raw_penalty * 10))
    return round(readiness, 1)


def enrich_cbom(cbom_json: Union[str, Path, Dict[str, Any], None] = None) -> Dict[str, Any]:
    """
    Enriches CBOM components with Mosca's quantum risk metrics and Crypto Agility Scores (CAS).
    Saves the enriched structure to cbom_enriched.json.
    """
    if cbom_json is None:
        source_path = Path(__file__).parent / "cbom_output.json"
        with open(source_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(cbom_json, (str, Path)):
        source_path = Path(cbom_json)
        if not source_path.exists():
            source_path = Path(__file__).parent / source_path.name
        with open(source_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(cbom_json, dict):
        data = cbom_json
    else:
        raise ValueError(f"Unsupported cbom_json input: {type(cbom_json)}")

    components: List[Dict[str, Any]] = data.get("components", [])

    for component in components:
        algo_name = component.get("name", "").upper()
        params = DEMO_PARAMS.get(
            algo_name,
            {"data_lifetime": 5, "migration_time": 2, "criticality": 5, "migration_effort": 3}
        )

        # 1. Compute Mosca's theorem risk metrics
        risk_data = mosca_risk(
            data_lifetime_years=params["data_lifetime"],
            migration_time_years=params["migration_time"]
        )

        # 2. Compute Crypto Agility Score (CAS)
        # risk_score = urgency_score * 5, capped at 10
        risk_score = min(10.0, risk_data["urgency_score"] * 5)
        cas = crypto_agility_score(
            risk_score=risk_score,
            criticality_weight=params["criticality"],
            migration_effort=params["migration_effort"]
        )

        # 3. Add enriched risk keys
        component["riskAssessment"] = risk_data
        component["cryptoAgilityScore"] = cas

    # Save enriched result to cbom_enriched.json in project root
    output_path = Path(__file__).parent / "cbom_enriched.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return data


if __name__ == "__main__":
    cbom_file = Path(__file__).parent / "cbom_output.json"
    if not cbom_file.exists():
        cbom_file = Path("./cbom_output.json")

    enriched_data = enrich_cbom(str(cbom_file))
    components = enriched_data.get("components", [])

    print("=" * 70)
    print("           ECDAT Cryptographic Risk Assessment Summary")
    print("=" * 70)
    header = f"{'Algorithm':<14} | {'At Risk Now':<13} | {'Urgency Score':<15} | {'CAS Score':<10}"
    print(header)
    print("-" * 70)

    for comp in components:
        name = comp.get("name", "N/A")
        risk = comp.get("riskAssessment", {})
        at_risk = str(risk.get("at_risk_now", "N/A"))
        urgency = f"{risk.get('urgency_score', 0.0):.2f}"
        cas = f"{comp.get('cryptoAgilityScore', 0.0):.1f}"
        print(f"{name:<14} | {at_risk:<13} | {urgency:<15} | {cas:<10}")

    print("=" * 70)
    print(f"Enriched CBOM saved to: {Path(__file__).parent / 'cbom_enriched.json'}")

