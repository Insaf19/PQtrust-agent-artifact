#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
OPENSSL="${REPO_ROOT}/.local/openssl-3.5.7/bin/openssl"
ROOT="${REPO_ROOT}/.local/pqtrust-crypto/agents"
MANIFEST="${REPO_ROOT}/artifacts/protocol/agent_evidence_key_manifest.json"

agents=(
  cloud-orchestrator
  public-tool-agent
  enterprise-api-agent
  edge-control-agent
  quantum-ready-tool-agent
)
algorithms=("ML-DSA-65" "ML-DSA-87")

key_stem() {
  local agent_dir="$1" algorithm="$2" canonical legacy
  case "${algorithm}" in
    ML-DSA-65)
      canonical="mldsa65"
      legacy="mlzdsaz65"
      ;;
    ML-DSA-87)
      canonical="mldsa87"
      legacy="mlzdsaz87"
      ;;
    *)
      echo "unsupported evidence algorithm: ${algorithm}" >&2
      exit 1
      ;;
  esac
  if [[ -e "${agent_dir}/${legacy}.private.pem" || -e "${agent_dir}/${legacy}.public.pem" ]]; then
    printf '%s' "${legacy}"
  else
    printf '%s' "${canonical}"
  fi
}

if [[ ! -x "${OPENSSL}" ]]; then
  echo "repository-local OpenSSL executable is missing: ${OPENSSL}" >&2
  exit 1
fi

validate_pair() {
  local private="$1" public="$2"
  "${OPENSSL}" pkey -in "${private}" -noout >/dev/null
  "${OPENSSL}" pkey -pubin -in "${public}" -noout >/dev/null
  local msg sig
  msg="$(mktemp)"
  sig="$(mktemp)"
  printf 'PQTrust Stage 5 laboratory evidence key validation\n' > "${msg}"
  "${OPENSSL}" pkeyutl -sign -rawin -inkey "${private}" -in "${msg}" -out "${sig}" >/dev/null
  test -s "${sig}"
  "${OPENSSL}" pkeyutl -verify -rawin -pubin -inkey "${public}" -in "${msg}" -sigfile "${sig}" >/dev/null
  rm -f "${msg}" "${sig}"
}

for agent in "${agents[@]}"; do
  agent_dir="${ROOT}/${agent}"
  mkdir -p "${agent_dir}"
  chmod 700 "${agent_dir}"
  for algorithm in "${algorithms[@]}"; do
    stem="$(key_stem "${agent_dir}" "${algorithm}")"
    private="${agent_dir}/${stem}.private.pem"
    public="${agent_dir}/${stem}.public.pem"
    if [[ -e "${private}" || -e "${public}" ]]; then
      if [[ ! -f "${private}" || ! -f "${public}" ]]; then
        echo "partial key material for ${agent} ${algorithm}; refusing to continue" >&2
        exit 1
      fi
      mode="$(stat -c '%a' "${private}")"
      if [[ "${mode}" != "600" ]]; then
        echo "private key permissions must be 0600: ${private}" >&2
        exit 1
      fi
      validate_pair "${private}" "${public}"
      continue
    fi
    tmp_private="${private}.tmp.$$"
    tmp_public="${public}.tmp.$$"
    "${OPENSSL}" genpkey -algorithm "${algorithm}" -out "${tmp_private}"
    chmod 600 "${tmp_private}"
    "${OPENSSL}" pkey -in "${tmp_private}" -pubout -out "${tmp_public}"
    validate_pair "${tmp_private}" "${tmp_public}"
    mv "${tmp_private}" "${private}"
    mv "${tmp_public}" "${public}"
  done
done

python3 - <<'PY'
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

repo = Path.cwd()
root = repo / ".local/pqtrust-crypto/agents"
manifest = repo / "artifacts/protocol/agent_evidence_key_manifest.json"
records = []
def canonical_algorithm(stem: str) -> str:
    normalized = stem.strip().upper().replace("_", "-")
    aliases = {
        "ML-DSA-65": "ML-DSA-65",
        "ML-DSA-87": "ML-DSA-87",
        "MLDSA65": "ML-DSA-65",
        "MLDSA87": "ML-DSA-87",
        "MLDSA-65": "ML-DSA-65",
        "MLDSA-87": "ML-DSA-87",
        "MLZDSAZ65": "ML-DSA-65",
        "MLZDSAZ87": "ML-DSA-87",
    }
    try:
        return aliases[normalized]
    except KeyError as exc:
        raise SystemExit(f"unsupported evidence key filename stem: {stem}") from exc

for public in sorted(root.glob("*/*.public.pem")):
    agent_id = public.parent.name
    algorithm = canonical_algorithm(public.name.removesuffix(".public.pem"))
    records.append(
        {
            "agent_id": agent_id,
            "algorithm": algorithm,
            "key_id": f"{agent_id}:{algorithm}:lab-v1",
            "public_key_sha256": hashlib.sha256(public.read_bytes()).hexdigest(),
            "local_relative_path": public.relative_to(repo).as_posix(),
            "validation_status": "validated",
        }
    )
payload = {"manifest_version": "1.0", "laboratory_only": True, "keys": records}
manifest.parent.mkdir(parents=True, exist_ok=True)
tmp = manifest.with_name(".agent_evidence_key_manifest.json.tmp")
tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.replace(tmp, manifest)
PY

echo "generated and validated laboratory-only agent evidence keys"
