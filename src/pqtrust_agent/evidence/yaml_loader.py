"""Duplicate-safe YAML loading for typed evidence and configuration files."""

from __future__ import annotations

from pathlib import Path
from typing import TypeVar

import yaml
from pydantic import BaseModel, TypeAdapter
from yaml.nodes import MappingNode

from pqtrust_agent.exceptions import PolicyValidationError


class DuplicateKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_mapping_no_duplicates(
    loader: DuplicateKeySafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise PolicyValidationError(f"duplicate YAML key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


DuplicateKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping_no_duplicates,
)

ModelT = TypeVar("ModelT", bound=BaseModel)


def load_yaml_document(path: Path) -> object:
    """Load a non-empty YAML document from ``path`` with duplicate-key rejection."""

    try:
        raw = yaml.load(path.read_text(encoding="utf-8"), Loader=DuplicateKeySafeLoader)
    except PolicyValidationError as exc:
        raise PolicyValidationError(f"{path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise PolicyValidationError(f"{path}: {exc}") from exc
    if raw is None:
        raise PolicyValidationError(f"{path}: YAML document must not be empty")
    return raw


def load_yaml_model(path: Path, model: type[ModelT]) -> ModelT:
    """Load and validate a Pydantic model from YAML."""

    raw = load_yaml_document(path)
    try:
        return model.model_validate(raw)
    except Exception as exc:
        raise PolicyValidationError(f"{path}: {exc}") from exc


def load_yaml_type(path: Path, adapter: TypeAdapter[ModelT]) -> ModelT:
    """Load and validate a Pydantic type adapter from YAML."""

    raw = load_yaml_document(path)
    try:
        return adapter.validate_python(raw)
    except Exception as exc:
        raise PolicyValidationError(f"{path}: {exc}") from exc
