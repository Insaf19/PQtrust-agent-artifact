#!/usr/bin/env bash

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  printf 'error: this script must be sourced, not executed\n' >&2
  printf 'usage: source scripts/activate_local_openssl.sh\n' >&2
  exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
openssl_prefix="${repo_root}/.local/openssl-3.5.7"
openssl_bin_dir="${openssl_prefix}/bin"
openssl_lib_dir="${openssl_prefix}/lib"
openssl_modules_dir="${openssl_lib_dir}/ossl-modules"
openssl_bin="${openssl_bin_dir}/openssl"

if [[ ! -x "$openssl_bin" ]]; then
  printf 'error: local OpenSSL executable not found: %s\n' "$openssl_bin" >&2
  return 1
fi

export PATH="${openssl_bin_dir}:${PATH}"
export LD_LIBRARY_PATH="${openssl_lib_dir}:${LD_LIBRARY_PATH:-}"

if [[ -d "$openssl_modules_dir" ]]; then
  export OPENSSL_MODULES="$openssl_modules_dir"
fi

printf 'Selected OpenSSL executable: %s\n' "$(command -v openssl)"
openssl version
