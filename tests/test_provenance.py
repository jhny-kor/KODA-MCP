from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from koda_mcp.standard_catalog_data import SOURCE_COMMIT, SOURCE_SHA256


ROOT = Path(__file__).resolve().parents[1]


class ProvenanceTests(unittest.TestCase):
    def test_source_verifier_and_recorded_hashes(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "verify_source.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        provenance = json.loads((ROOT / "SOURCE_PROVENANCE.json").read_text(encoding="utf-8"))
        self.assertTrue((ROOT / "LICENSE").is_file())
        self.assertTrue((ROOT / "NOTICE").is_file())
        for entry in provenance["files"]:
            path = ROOT / entry["target_path"]
            if entry["kind"] in {"copied", "derived"}:
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), entry["sha256"])
        derived = next(entry for entry in provenance["files"] if entry["kind"] == "derived")
        self.assertEqual((provenance["source"]["commit"], derived["source_sha256"]), (SOURCE_COMMIT, SOURCE_SHA256))


if __name__ == "__main__":
    unittest.main()
