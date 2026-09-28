"""Risk classification, Mosca assessment and crypto-agility scoring."""
from copy import deepcopy


DEFAULT_PROFILE = {
    "data_lifetime_years": 10,
    "migration_time_years": 3,
    "criticality": 5,
    "crqc_arrival_years": 10,
}

QUANTUM_VULNERABLE = {"RSA", "ECDSA", "ECDH", "Ed25519", "DSA", "DH"}
WEAK_ALGORITHMS = {"MD5", "SHA1", "DES", "3DES", "RC4", "ECB"}
PQC_RECOMMENDATIONS = {
    "RSA": "For encryption, plan a ML-KEM (FIPS 203) hybrid migration. For signatures, plan ML-DSA (FIPS 204) or SLH-DSA (FIPS 205), after validating protocol compatibility.",
    "ECDSA": "Plan ML-DSA (FIPS 204) or a hybrid signature migration after validating protocol compatibility.",
    "ECDH": "Plan an ML-KEM (FIPS 203) hybrid key-establishment migration after validating protocol compatibility.",
    "Ed25519": "Plan a post-quantum signature migration such as ML-DSA (FIPS 204), retaining a hybrid transition where needed.",
}


def normalize_profile(profile=None):
    values = {**DEFAULT_PROFILE, **(profile or {})}
    normalized = {}
    for name, default in DEFAULT_PROFILE.items():
        try:
            value = int(values.get(name, default))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be a whole number") from exc
        if name == "criticality" and not 1 <= value <= 10:
            raise ValueError("criticality must be between 1 and 10")
        if name != "criticality" and not 0 <= value <= 100:
            raise ValueError(f"{name} must be between 0 and 100")
        normalized[name] = value
    return normalized


def mosca_risk(data_lifetime_years, migration_time_years, crqc_arrival_years):
    exposure = data_lifetime_years + migration_time_years
    return {
        "data_lifetime_years": data_lifetime_years,
        "migration_time_years": migration_time_years,
        "crqc_arrival_years": crqc_arrival_years,
        "at_risk_now": exposure > crqc_arrival_years,
        "urgency_score": round(exposure / crqc_arrival_years, 2) if crqc_arrival_years else None,
    }


def crypto_agility_score(risk_score, criticality, migration_effort):
    penalty = risk_score * 0.5 + criticality * 0.3 + migration_effort * 0.2
    return round(max(0, 100 - penalty * 10), 1)


def classify_finding(finding):
    name = finding.get("pattern", "UNKNOWN")
    if name in QUANTUM_VULNERABLE:
        return "classical-public-key", True, 7, PQC_RECOMMENDATIONS.get(name, finding.get("recommendation", ""))
    if name in WEAK_ALGORITHMS:
        return "legacy-or-weak", False, 10, finding.get("recommendation", "")
    if name == "Private key":
        return "key-material", False, 9, "Move private keys out of source or image layers, rotate exposed keys, and use managed secret storage."
    if name == "Certificate":
        return "certificate", False, 4, finding.get("recommendation", "")
    if name in {"ML-KEM", "ML-DSA"}:
        return "post-quantum", False, 1, finding.get("recommendation", "")
    return "symmetric-or-hash", False, 2, finding.get("recommendation", "")


def assess_findings(findings, profile=None):
    profile = normalize_profile(profile)
    assessed = []
    for original in findings:
        finding = deepcopy(original)
        asset_type, quantum_vulnerable, base_risk, recommendation = classify_finding(finding)
        metadata = finding.get("metadata", {})
        if metadata.get("expired"):
            base_risk = 10
        mosca = mosca_risk(
            profile["data_lifetime_years"],
            profile["migration_time_years"],
            profile["crqc_arrival_years"],
        )
        if quantum_vulnerable and mosca["at_risk_now"]:
            base_risk = min(10, base_risk + 2)
        effort = 8 if quantum_vulnerable else 5 if asset_type in {"legacy-or-weak", "key-material"} else 3
        finding["classification"] = asset_type
        finding["quantum_vulnerable"] = quantum_vulnerable
        finding["riskAssessment"] = {**mosca, "risk_score": base_risk}
        finding["cryptoAgilityScore"] = crypto_agility_score(base_risk, profile["criticality"], effort)
        finding["recommendation"] = recommendation
        assessed.append(finding)
    scores = [finding["cryptoAgilityScore"] for finding in assessed]
    return assessed, {
        "profile": profile,
        "assets_assessed": len(assessed),
        "quantum_vulnerable_assets": sum(finding["quantum_vulnerable"] for finding in assessed),
        "at_risk_now": sum(finding["quantum_vulnerable"] and finding["riskAssessment"]["at_risk_now"] for finding in assessed),
        "average_crypto_agility_score": round(sum(scores) / len(scores), 1) if scores else None,
    }
