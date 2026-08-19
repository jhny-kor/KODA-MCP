#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_sha256(entries: list[dict[str, object]]) -> str:
    digest = hashlib.sha256()
    copied = sorted(
        (str(entry["target_path"]), str(entry["sha256"]))
        for entry in entries
        if entry.get("kind") == "copied"
    )
    for target_path, file_hash in copied:
        digest.update(f"{target_path}\0{file_hash}\n".encode("utf-8"))
    return digest.hexdigest()


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    provenance_path = root / "SOURCE_PROVENANCE.json"
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        entries = provenance["files"]
        source = provenance["source"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        print(f"source verification failed: invalid provenance ({exc})", file=sys.stderr)
        return 1

    if source.get("commit") != "b2987c1211e745aa9dc99db94e0ad7eb73cc11e4":
        print("source verification failed: unexpected source commit", file=sys.stderr)
        return 1
    if source.get("url") != "https://github.com/jhny-kor/sec-chk.git":
        print("source verification failed: unexpected source URL", file=sys.stderr)
        return 1

    targets: set[str] = set()
    for entry in entries:
        target_path = entry.get("target_path")
        if not isinstance(target_path, str) or target_path in targets:
            print("source verification failed: duplicate or invalid target path", file=sys.stderr)
            return 1
        targets.add(target_path)
        path = root / target_path
        if not path.is_file():
            print(f"source verification failed: missing {target_path}", file=sys.stderr)
            return 1
        if entry.get("kind") in {"copied", "derived"} and _sha256(path) != entry.get("sha256"):
            print(f"source verification failed: hash mismatch {target_path}", file=sys.stderr)
            return 1
        if entry.get("kind") == "generated" and path.read_bytes().strip() != b"":
            print(f"source verification failed: generated file is not empty {target_path}", file=sys.stderr)
            return 1

    core_root = root / "src" / "koda_core"
    actual = {
        path.relative_to(root).as_posix()
        for path in core_root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }
    expected = {path for path in targets if path.startswith("src/koda_core/")}
    if actual != expected:
        extra = sorted(actual - expected)
        missing = sorted(expected - actual)
        print(f"source verification failed: core allowlist mismatch extra={extra} missing={missing}", file=sys.stderr)
        return 1

    for target_path in ("LICENSE", "NOTICE"):
        if target_path not in targets:
            print(f"source verification failed: missing {target_path} provenance", file=sys.stderr)
            return 1

    if provenance.get("source_tree_sha256") != _tree_sha256(entries):
        print("source verification failed: source tree hash mismatch", file=sys.stderr)
        return 1

    print(f"source verified: {len(entries)} files, commit={source['commit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
