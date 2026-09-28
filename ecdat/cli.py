"""Command-line entry point for local ECDAT scans."""
import argparse
import json
from pathlib import Path

from cbom_builder import build_cbom
from risk_engine import assess_findings
from scanner import Scanner


def main():
    parser = argparse.ArgumentParser(description="Scan a directory for cryptographic assets.")
    parser.add_argument("target", type=Path, help="Directory to scan")
    parser.add_argument("--output", type=Path, default=Path("ecdat-report.json"), help="Report JSON path")
    parser.add_argument("--data-lifetime-years", type=int, default=10)
    parser.add_argument("--migration-time-years", type=int, default=3)
    parser.add_argument("--criticality", type=int, default=5)
    parser.add_argument("--crqc-arrival-years", type=int, default=10)
    arguments = parser.parse_args()
    raw = Scanner().directory(arguments.target)
    profile = {
        "data_lifetime_years": arguments.data_lifetime_years,
        "migration_time_years": arguments.migration_time_years,
        "criticality": arguments.criticality,
        "crqc_arrival_years": arguments.crqc_arrival_years,
    }
    findings, risk_summary = assess_findings(raw["findings"], profile)
    report = {**raw, "findings": findings, "profile": risk_summary.pop("profile"), "risk_summary": risk_summary}
    report["cbom"] = build_cbom(findings)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Scanned {report['stats']['files_scanned']} files; found {len(findings)} crypto assets.")
    print(f"Report written to {arguments.output.resolve()}")
    return 1 if any(finding["severity"] == "high" for finding in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
