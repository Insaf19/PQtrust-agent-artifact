#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
OPENSSL_PREFIX="${REPO_ROOT}/.local/openssl-3.5.7"
OPENSSL_BIN="${OPENSSL_PREFIX}/bin/openssl"
OPENSSL_INCLUDE="${OPENSSL_PREFIX}/include"
OPENSSL_LIB="${OPENSSL_PREFIX}/lib"

require_path() {
  local path="$1"
  if [[ ! -e "${path}" ]]; then
    echo "required path is missing: ${path}" >&2
    exit 1
  fi
}

require_path "${OPENSSL_BIN}"
require_path "${OPENSSL_INCLUDE}"
require_path "${OPENSSL_LIB}"

version="$("${OPENSSL_BIN}" version | awk '{print $2}')"
if [[ "${version}" != "3.5.7" ]]; then
  echo "repository-local OpenSSL must be exactly 3.5.7, got: ${version}" >&2
  exit 1
fi

make -C "${REPO_ROOT}/native" clean
make -C "${REPO_ROOT}/native" build CC=gcc OPENSSL_PREFIX="${OPENSSL_PREFIX}"

for binary in "${REPO_ROOT}/.build/native/tls_handshake_bench" \
              "${REPO_ROOT}/.build/native/mldsa_bench"; do
  echo "ldd ${binary}"
  ldd "${binary}"
  while IFS= read -r line; do
    case "${line}" in
      *libssl.so*|*libcrypto.so*)
        if [[ "${line}" != *"${OPENSSL_PREFIX}/lib/"* ]]; then
          echo "invalid OpenSSL linkage for ${binary}: ${line}" >&2
          exit 1
        fi
        ;;
    esac
  done < <(ldd "${binary}")
done
