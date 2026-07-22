"""Local replay registries for laboratory validation."""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pqtrust_agent.protocol.time import require_contract_active, require_utc_aware


class ReplayRegistry(ABC):
    @abstractmethod
    def register_session(self, session_id: str, *, reference_time: datetime) -> None: ...

    @abstractmethod
    def register_commitment(
        self,
        session_id: str,
        commitment: str,
        *,
        reference_time: datetime,
    ) -> None: ...

    @abstractmethod
    def register_transcript(
        self,
        session_id: str,
        transcript_hash: str,
        *,
        reference_time: datetime,
    ) -> None: ...

    @abstractmethod
    def register_contract(
        self,
        *,
        contract_id: str,
        contract_hash: str,
        session_id: str,
        issued_at: datetime,
        expires_at: datetime,
        activation_time: datetime,
    ) -> None: ...


class InMemoryReplayRegistry(ReplayRegistry):
    """Process-local replay registry used by tests."""

    def __init__(self) -> None:
        self.sessions: set[str] = set()
        self.commitments: dict[str, str] = {}
        self.transcripts: set[str] = set()
        self.contracts: dict[str, dict[str, Any]] = {}

    def _cleanup_expired_contracts(self, *, reference_time: datetime) -> None:
        reference = require_utc_aware(reference_time, phase="replay_cleanup")
        self.contracts = {
            contract_id: entry
            for contract_id, entry in self.contracts.items()
            if datetime.fromisoformat(entry["expires_at"]) > reference
        }

    def register_session(self, session_id: str, *, reference_time: datetime) -> None:
        self._cleanup_expired_contracts(reference_time=reference_time)
        if session_id in self.sessions:
            raise ValueError("replayed session ID")
        self.sessions.add(session_id)

    def register_commitment(
        self,
        session_id: str,
        commitment: str,
        *,
        reference_time: datetime,
    ) -> None:
        self._cleanup_expired_contracts(reference_time=reference_time)
        owner = self.commitments.get(commitment)
        if owner is not None and owner != session_id:
            raise ValueError("replayed commitment in different session")
        if owner == session_id:
            raise ValueError("duplicate commitment")
        self.commitments[commitment] = session_id

    def register_transcript(
        self,
        session_id: str,
        transcript_hash: str,
        *,
        reference_time: datetime,
    ) -> None:
        self._cleanup_expired_contracts(reference_time=reference_time)
        del session_id
        if transcript_hash in self.transcripts:
            raise ValueError("duplicate transcript hash")
        self.transcripts.add(transcript_hash)

    def register_contract(
        self,
        *,
        contract_id: str,
        contract_hash: str,
        session_id: str,
        issued_at: datetime,
        expires_at: datetime,
        activation_time: datetime,
    ) -> None:
        activation = require_contract_active(
            issued_at=issued_at,
            expires_at=expires_at,
            activation_time=activation_time,
            phase="replay_contract_registration",
        )
        self._cleanup_expired_contracts(reference_time=activation)
        existing = self.contracts.get(contract_id)
        if existing is not None and datetime.fromisoformat(existing["expires_at"]) > activation:
            raise ValueError("duplicate active contract ID")
        self.contracts[contract_id] = {
            "contract_hash": contract_hash,
            "session_id": session_id,
            "issued_at": issued_at.astimezone(UTC).isoformat(),
            "expires_at": expires_at.astimezone(UTC).isoformat(),
            "activation_time": activation.isoformat(),
        }


class JsonFileReplayRegistry(InMemoryReplayRegistry):
    """Atomic JSON-file registry for single-host laboratory validation."""

    def __init__(self, path: Path) -> None:
        self.path = path
        if path.exists():
            raw = json.loads(path.read_text(encoding="utf-8"))
            self.sessions = set(raw.get("sessions", []))
            self.commitments = dict(raw.get("commitments", {}))
            self.transcripts = set(raw.get("transcripts", []))
            self.contracts = dict(raw.get("contracts", {}))
        else:
            super().__init__()

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "sessions": sorted(self.sessions),
            "commitments": dict(sorted(self.commitments.items())),
            "transcripts": sorted(self.transcripts),
            "contracts": self.contracts,
        }
        tmp = self.path.with_name(f".{self.path.name}.tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)

    def register_session(self, session_id: str, *, reference_time: datetime) -> None:
        super().register_session(session_id, reference_time=reference_time)
        self._flush()

    def register_commitment(
        self,
        session_id: str,
        commitment: str,
        *,
        reference_time: datetime,
    ) -> None:
        super().register_commitment(session_id, commitment, reference_time=reference_time)
        self._flush()

    def register_transcript(
        self,
        session_id: str,
        transcript_hash: str,
        *,
        reference_time: datetime,
    ) -> None:
        super().register_transcript(session_id, transcript_hash, reference_time=reference_time)
        self._flush()

    def register_contract(
        self,
        *,
        contract_id: str,
        contract_hash: str,
        session_id: str,
        issued_at: datetime,
        expires_at: datetime,
        activation_time: datetime,
    ) -> None:
        super().register_contract(
            contract_id=contract_id,
            contract_hash=contract_hash,
            session_id=session_id,
            issued_at=issued_at,
            expires_at=expires_at,
            activation_time=activation_time,
        )
        self._flush()
