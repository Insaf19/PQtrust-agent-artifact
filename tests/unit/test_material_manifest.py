from __future__ import annotations

import hashlib
from pathlib import Path

from pqtrust_agent.crypto.material_manifest import repo_relative, sha256_file


def test_sha256_file(tmp_path: Path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"not a scientific measurement")
    assert sha256_file(path) == hashlib.sha256(b"not a scientific measurement").hexdigest()


def test_repo_relative(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    child = repo / "artifacts" / "manifest.json"
    child.parent.mkdir(parents=True)
    child.write_text("{}", encoding="utf-8")
    assert repo_relative(repo, child) == "artifacts/manifest.json"
