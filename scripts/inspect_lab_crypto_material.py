#!/usr/bin/env python3
"""Inspect laboratory-only cryptographic material and write a metadata manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pqtrust_agent.crypto.material_manifest import (
    ManifestContext,
    create_material_manifest,
    write_manifest,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--material-dir", type=Path, default=Path(".local/pqtrust-crypto"))
    parser.add_argument(
        "--openssl",
        type=Path,
        default=Path(".local/openssl-3.5.7/bin/openssl"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/environment/lab_crypto_material_manifest.json"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    context = ManifestContext(
        repo_root=repo_root,
        material_dir=(repo_root / args.material_dir).resolve()
        if not args.material_dir.is_absolute()
        else args.material_dir.resolve(),
        openssl_executable=(repo_root / args.openssl).resolve()
        if not args.openssl.is_absolute()
        else args.openssl.resolve(),
    )
    manifest = create_material_manifest(context)
    output = repo_root / args.output if not args.output.is_absolute() else args.output
    write_manifest(manifest, output)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0 if manifest["validation_passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
