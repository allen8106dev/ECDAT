"""
api.py - FastAPI backend for ECDAT (Enterprise Cryptographic Discovery and Audit Tool).
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from audit_chain import AuditChain
from cbom_builder import build_cbom
from patch_generator import generate_all_patches
from risk_engine import enrich_cbom
from scanner import scan_directory

app = FastAPI(title="ECDAT API", version="1.0.0")

# CORS middleware for React dashboard
origins = [
    "http://localhost:5173",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PROJECT_ROOT = Path(__file__).parent
DEMO_DATA_DIR = PROJECT_ROOT / "demo-data"
CBOM_OUTPUT_PATH = PROJECT_ROOT / "cbom_output.json"
CBOM_ENRICHED_PATH = PROJECT_ROOT / "cbom_enriched.json"
AUDIT_LOG_PATH = PROJECT_ROOT / "audit_log.json"


@app.get("/")
def health_check() -> Dict[str, str]:
    """Health check endpoint."""
    return {"status": "ECDAT API running"}


@app.post("/scan")
def run_scan() -> Dict[str, Any]:
    """
    Runs scan_directory("./demo-data"), builds and enriches the CBOM,
    records the event in the audit chain, and returns summary metadata.
    """
    scan_dir = DEMO_DATA_DIR if DEMO_DATA_DIR.exists() else Path("./demo-data")
    findings = scan_directory(str(scan_dir))

    # Build and persist base CBOM
    cbom = build_cbom(findings)
    with open(CBOM_OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(cbom, f, indent=2)

    # Enrich and persist CBOM
    enriched_cbom = enrich_cbom(cbom)
    with open(CBOM_ENRICHED_PATH, "w", encoding="utf-8") as f:
        json.dump(enriched_cbom, f, indent=2)

    # Append to audit chain
    chain = AuditChain()
    if AUDIT_LOG_PATH.exists():
        try:
            chain.load_from_file(AUDIT_LOG_PATH)
        except Exception:
            chain = AuditChain()

    new_block = chain.add_scan_record(enriched_cbom)
    chain.save_to_file(AUDIT_LOG_PATH)

    components_count = len(enriched_cbom.get("components", []))

    return {
        "status": "success",
        "components_found": components_count,
        "audit_block_hash": new_block.get("hash", ""),
    }


@app.get("/cbom")
def get_cbom() -> Dict[str, Any]:
    """Loads and returns the full contents of cbom_enriched.json."""
    if not CBOM_ENRICHED_PATH.exists():
        raise HTTPException(status_code=404, detail="CBOM not found. Run POST /scan first.")

    with open(CBOM_ENRICHED_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@app.get("/patches")
def get_patches() -> List[Dict[str, Any]]:
    """
    Runs generate_all_patches() and returns patch results with diff as a list of lines.
    """
    scan_dir = DEMO_DATA_DIR if DEMO_DATA_DIR.exists() else Path("./demo-data")
    raw_patches = generate_all_patches(scan_dir)

    formatted_patches: List[Dict[str, Any]] = []
    for patch in raw_patches:
        diff_lines = patch.get("diff", "").splitlines()
        formatted_patches.append(
            {
                "file": patch.get("file_name", patch.get("file_path", "")),
                "changes": patch.get("changes", []),
                "diff": diff_lines,
            }
        )

    return formatted_patches


@app.get("/audit/verify")
def verify_audit() -> Dict[str, Any]:
    """
    Loads audit_log.json, creates an AuditChain, and verifies chain integrity.
    """
    if not AUDIT_LOG_PATH.exists():
        raise HTTPException(
            status_code=404, detail="Audit log not found. Run POST /scan first."
        )

    chain = AuditChain()
    chain.load_from_file(AUDIT_LOG_PATH)
    is_valid, broken_index = chain.verify_chain()

    return {
        "is_valid": is_valid,
        "broken_index": broken_index,
    }

