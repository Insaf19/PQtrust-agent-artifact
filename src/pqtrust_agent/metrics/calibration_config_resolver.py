"""Resolve immutable calibration run configurations from raw-run snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from pqtrust_agent.metrics.calibration_models import CryptoCalibrationConfig
from pqtrust_agent.metrics.validation import load_json


class DuplicateKeyError(ValueError):
    """Raised when a YAML mapping contains a duplicate key."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: yaml.Loader, node: yaml.Node, deep: bool = False) -> Any:
    if not isinstance(node, yaml.MappingNode):
        raise ValueError("expected a YAML mapping node")
    seen: set[Any] = set()
    for key_node, _value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise DuplicateKeyError(f"duplicate YAML key: {key}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


@dataclass(frozen=True)
class ResolvedCalibrationConfig:
    config: CryptoCalibrationConfig
    run_dir: Path
    snapshot_path: Path
    manifest_path: Path
    manifest: dict[str, Any]
    exact_configuration_hash: str
    legacy_configuration_hash: str
    scientific_design_hash: str
    manifest_configuration_hash: str | None
    manifest_configuration_hash_matches: bool
    manifest_hash_field: str | None


def load_calibration_config_strict(path: Path) -> CryptoCalibrationConfig:
    loaded = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return CryptoCalibrationConfig.model_validate(loaded)


def _manifest_hash(manifest: dict[str, Any]) -> tuple[str | None, str | None]:
    exact = manifest.get("exact_configuration_hash")
    if isinstance(exact, str):
        return exact, "exact_configuration_hash"
    legacy = manifest.get("calibration_configuration_hash")
    if isinstance(legacy, str):
        return legacy, "calibration_configuration_hash"
    return None, None


def resolve_raw_run_config(run_dir: Path) -> ResolvedCalibrationConfig:
    snapshot_path = run_dir / "config_snapshot.yaml"
    manifest_path = run_dir / "run_manifest.json"
    config = load_calibration_config_strict(snapshot_path)
    manifest = load_json(manifest_path)
    exact_hash = config.exact_configuration_hash()
    legacy_hash = config.config_hash()
    scientific_hash = config.scientific_design_hash()
    manifest_hash, manifest_field = _manifest_hash(manifest)
    matches = manifest_hash in {exact_hash, legacy_hash}
    if not matches:
        raise ValueError(
            "run manifest configuration hash mismatch: "
            f"manifest={manifest_hash!r}, exact={exact_hash}, legacy={legacy_hash}"
        )
    return ResolvedCalibrationConfig(
        config=config,
        run_dir=run_dir,
        snapshot_path=snapshot_path,
        manifest_path=manifest_path,
        manifest=manifest,
        exact_configuration_hash=exact_hash,
        legacy_configuration_hash=legacy_hash,
        scientific_design_hash=scientific_hash,
        manifest_configuration_hash=manifest_hash,
        manifest_configuration_hash_matches=matches,
        manifest_hash_field=manifest_field,
    )


def resolve_raw_run_config_with_optional_external(
    run_dir: Path,
    external_config_path: Path | None,
) -> ResolvedCalibrationConfig:
    resolved = resolve_raw_run_config(run_dir)
    if external_config_path is None:
        return resolved
    external = load_calibration_config_strict(external_config_path)
    external_hash = external.exact_configuration_hash()
    snapshot_hash = resolved.exact_configuration_hash
    if external_hash != snapshot_hash:
        raise ValueError(
            "external configuration does not match raw-run snapshot: "
            f"external_path={external_config_path}, snapshot_path={resolved.snapshot_path}, "
            f"external_exact_hash={external_hash}, snapshot_exact_hash={snapshot_hash}"
        )
    return resolved
