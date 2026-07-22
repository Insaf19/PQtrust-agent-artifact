"""Structured protocol validation errors."""

from __future__ import annotations

from datetime import datetime
from typing import Any


class ProtocolTimeError(ValueError):
    """Stable time-dependent protocol failure with machine-readable evidence."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        phase: str,
        reference_time: datetime | None = None,
        scenario_id: str | None = None,
        **evidence: Any,
    ) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.phase = phase
        self.reference_time = reference_time
        self.scenario_id = scenario_id
        self.evidence = evidence

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "error_code": self.code,
            "message": self.message,
            "phase": self.phase,
            "supplied_reference_time": (
                self.reference_time.isoformat().replace("+00:00", "Z")
                if self.reference_time is not None
                else None
            ),
        }
        if self.scenario_id is not None:
            payload["scenario_id"] = self.scenario_id
        payload.update(self.evidence)
        return payload
