#!/usr/bin/env python3
"""Print the tree hash recorded as KODA_SOURCE_TREE_SHA256.

Run this after changing anything under src/koda_core and paste the result into
src/koda_mcp/scan_service.py, so the engine metadata in every scan response
keeps identifying the code that actually ran.
"""
from __future__ import annotations

import hashlib
from pathlib import Path


def tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(
        path
        for path in (root / "src" / "koda_core").rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    )
    for path in files:
        file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        digest.update(f"{path.relative_to(root).as_posix()}\0{file_hash}\n".encode("utf-8"))
    return digest.hexdigest()


if __name__ == "__main__":
    print(tree_sha256(Path(__file__).resolve().parents[1]))
