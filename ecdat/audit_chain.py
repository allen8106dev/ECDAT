"""
audit_chain.py - Cryptographic hash-chain for immutable scan result auditing.
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


class AuditChain:
    """Implements an immutable hash-chained audit log for CBOM scans."""

    def __init__(self) -> None:
        self.chain: List[Dict[str, Any]] = []

    def add_scan_record(self, cbom_json: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Hashes CBOM data, builds an audit block linked to the prior block, and appends it.
        """
        # Compute SHA-256 of the cbom_json with sorted keys
        if isinstance(cbom_json, dict):
            serialized_cbom = json.dumps(cbom_json, sort_keys=True)
        else:
            serialized_cbom = str(cbom_json)
        cbom_hash = hashlib.sha256(serialized_cbom.encode("utf-8")).hexdigest()

        # Compute previous_hash from the last block's hash (or "0" * 64 if empty)
        previous_hash = self.chain[-1]["hash"] if self.chain else "0" * 64

        # Build block
        block: Dict[str, Any] = {
            "timestamp": time.time(),
            "cbom_hash": cbom_hash,
            "previous_hash": previous_hash,
        }

        # Compute block's own hash (sha256 of block dict with sorted keys)
        serialized_block = json.dumps(block, sort_keys=True)
        block["hash"] = hashlib.sha256(serialized_block.encode("utf-8")).hexdigest()

        self.chain.append(block)
        return block

    def verify_chain(self) -> Tuple[bool, Optional[int]]:
        """
        Walks the chain to verify cryptographic integrity:
        - Each block's previous_hash must match the preceding block's hash.
        - Each block's content must hash to its own stored hash.
        Returns (True, None) if valid, or (False, index) of the first broken block.
        """
        for i, block in enumerate(self.chain):
            # 1. Verify previous_hash link
            expected_prev = self.chain[i - 1]["hash"] if i > 0 else "0" * 64
            if block.get("previous_hash") != expected_prev:
                return False, i

            # 2. Verify block's own hash against its contents
            block_content = {
                "timestamp": block["timestamp"],
                "cbom_hash": block["cbom_hash"],
                "previous_hash": block["previous_hash"],
            }
            recomputed_hash = hashlib.sha256(
                json.dumps(block_content, sort_keys=True).encode("utf-8")
            ).hexdigest()

            if recomputed_hash != block.get("hash"):
                return False, i

        return True, None

    def save_to_file(self, path: Union[str, Path]) -> None:
        """Persist the audit chain to a JSON file."""
        file_path = Path(path)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(self.chain, f, indent=2)

    def load_from_file(self, path: Union[str, Path]) -> None:
        """Load the audit chain from a JSON file."""
        file_path = Path(path)
        with open(file_path, "r", encoding="utf-8") as f:
            self.chain = json.load(f)


if __name__ == "__main__":
    project_root = Path(__file__).parent
    cbom_file = project_root / "cbom_enriched.json"
    audit_file = project_root / "audit_log.json"

    print("=" * 70)
    print("                     ECDAT Audit Chain Demo")
    print("=" * 70)

    # Step a: Load cbom_enriched.json
    if not cbom_file.exists():
        raise FileNotFoundError(f"Missing {cbom_file}. Run risk_engine.py first.")

    with open(cbom_file, "r", encoding="utf-8") as f:
        cbom_data = json.load(f)

    # Step b: Create AuditChain, add scan record, and save to audit_log.json
    chain = AuditChain()
    block = chain.add_scan_record(cbom_data)
    chain.save_to_file(audit_file)
    print(f"[+] Added block 0 for {cbom_file.name}")
    print(f"    CBOM Hash     : {block['cbom_hash']}")
    print(f"    Block Hash    : {block['hash']}")
    print(f"    Previous Hash : {block['previous_hash']}")
    print(f"[+] Saved initial chain to {audit_file.name}")
    print("-" * 70)

    # Step c: Verify before tampering
    print("Verification before tampering:")
    is_valid_before, broken_idx_before = chain.verify_chain()
    print(f"Result: is_valid={is_valid_before}, broken_index={broken_idx_before}")
    print("-" * 70)

    # Step d: Manually tamper with audit_log.json (flip one character in cbom_hash)
    with open(audit_file, "r", encoding="utf-8") as f:
        stored_chain = json.load(f)

    original_cbom_hash = stored_chain[0]["cbom_hash"]
    # Change the first hex character to '0' (or '1' if it was already '0')
    tampered_char = "1" if original_cbom_hash[0] == "0" else "0"
    tampered_cbom_hash = tampered_char + original_cbom_hash[1:]
    stored_chain[0]["cbom_hash"] = tampered_cbom_hash

    with open(audit_file, "w", encoding="utf-8") as f:
        json.dump(stored_chain, f, indent=2)

    print("[!] Simulated tampering on audit_log.json:")
    print(f"    Original cbom_hash : {original_cbom_hash}")
    print(f"    Tampered cbom_hash : {tampered_cbom_hash}")
    print("-" * 70)

    # Step e: Reload chain from the tampered file
    tampered_chain = AuditChain()
    tampered_chain.load_from_file(audit_file)

    # Step f: Verify after tampering
    print("Verification after tampering:")
    is_valid_after, broken_idx_after = tampered_chain.verify_chain()
    print(f"Result: is_valid={is_valid_after}, broken_index={broken_idx_after}")
    print("=" * 70)

