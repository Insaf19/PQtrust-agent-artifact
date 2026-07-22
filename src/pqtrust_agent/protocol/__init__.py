"""Stage 5 commit-reveal transcript and trust-contract helpers."""

from pqtrust_agent.protocol.commitment import (
    CommitRevealSession,
    create_commitment,
    production_nonce_hex,
    reveal_hash,
    verify_commitment,
)
from pqtrust_agent.protocol.contract_builder import (
    build_signed_contract,
    build_unsigned_contract,
)
from pqtrust_agent.protocol.replay import InMemoryReplayRegistry, JsonFileReplayRegistry
from pqtrust_agent.protocol.transcript import build_transcript, verify_transcript

__all__ = [
    "CommitRevealSession",
    "InMemoryReplayRegistry",
    "JsonFileReplayRegistry",
    "build_signed_contract",
    "build_transcript",
    "build_unsigned_contract",
    "create_commitment",
    "production_nonce_hex",
    "reveal_hash",
    "verify_commitment",
    "verify_transcript",
]
