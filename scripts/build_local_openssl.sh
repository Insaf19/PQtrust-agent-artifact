#!/usr/bin/env bash
set -euo pipefail

VERSION="3.5.7"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

cache_dir="${repo_root}/.cache/openssl"
build_parent="${repo_root}/.build"
build_dir="${build_parent}/openssl-${VERSION}"
prefix="${repo_root}/.local/openssl-${VERSION}"
local_perl_root="${repo_root}/.local/perl5"
local_perl_lib="${local_perl_root}/lib/perl5"
log_dir="${repo_root}/artifacts/environment"
log_file="${log_dir}/openssl-${VERSION}-build.log"
tarball="${cache_dir}/openssl-${VERSION}.tar.gz"
checksum_file="${cache_dir}/openssl-${VERSION}.tar.gz.sha256"
source_url="https://www.openssl.org/source/openssl-${VERSION}.tar.gz"
checksum_url="${source_url}.sha256"

log() {
  printf '%s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

download() {
  local url="$1"
  local output="$2"

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$output"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$url" -O "$output"
  else
    die "missing required downloader: curl or wget"
  fi
}

cpu_count() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
  elif command -v getconf >/dev/null 2>&1; then
    getconf _NPROCESSORS_ONLN
  else
    printf '1\n'
  fi
}

verify_checksum() {
  local checksum

  checksum="$(grep -Eo '[A-Fa-f0-9]{64}' "$checksum_file" | head -n 1 || true)"
  if [[ -z "$checksum" ]]; then
    die "could not parse SHA-256 checksum from ${checksum_file}"
  fi

  printf '%s  %s\n' "$checksum" "$tarball" | sha256sum -c -
}

verify_existing_install() {
  local openssl_bin="${prefix}/bin/openssl"

  if [[ ! -x "$openssl_bin" ]]; then
    return 1
  fi

  local version_output
  version_output="$(LD_LIBRARY_PATH="${prefix}/lib:${LD_LIBRARY_PATH:-}" "$openssl_bin" version)"
  [[ "$version_output" == OpenSSL\ ${VERSION}\ * ]]
}

main() {
  mkdir -p "$cache_dir" "$build_parent" "$log_dir"

  {
    log "OpenSSL ${VERSION} local build"
    log "Repository: ${repo_root}"
    log "Prefix: ${prefix}"
    log "Log: ${log_file}"
    log ""

    require_command gcc
    require_command make
    require_command perl
    require_command sha256sum
    require_command tar
    require_command gzip
    if [[ -d "$local_perl_lib" ]]; then
      export PERL5LIB="${local_perl_lib}${PERL5LIB:+:${PERL5LIB}}"
    fi
    perl -MText::Template -e 'exit 0' >/dev/null 2>&1 \
      || die "missing required Perl module: Text::Template
install it repository-locally with:
PERL_MM_USE_DEFAULT=1 cpan -l \"${local_perl_root}\" Text::Template"

    if verify_existing_install; then
      log "Valid local OpenSSL ${VERSION} installation already exists at ${prefix}"
      LD_LIBRARY_PATH="${prefix}/lib:${LD_LIBRARY_PATH:-}" "${prefix}/bin/openssl" version -a
      exit 0
    fi

    log "Downloading official OpenSSL tarball"
    download "$source_url" "$tarball"
    log "Downloading official OpenSSL SHA-256 checksum"
    download "$checksum_url" "$checksum_file"

    log "Verifying SHA-256 checksum"
    verify_checksum

    log "Extracting source"
    rm -rf "$build_dir"
    tar -xzf "$tarball" -C "$build_parent"

    cd "$build_dir"
    log "Configuring OpenSSL"
    ./Configure \
      "--prefix=${prefix}" \
      "--openssldir=${prefix}/ssl" \
      --libdir=lib

    local jobs
    jobs="$(cpu_count)"
    log "Building OpenSSL with ${jobs} job(s)"
    make "-j${jobs}"

    log "Running OpenSSL test suite"
    make test

    log "Installing OpenSSL into repository-local prefix"
    make install_sw install_ssldirs

    log "Verifying installed OpenSSL"
    verify_existing_install || die "installed OpenSSL ${VERSION} verification failed"
    LD_LIBRARY_PATH="${prefix}/lib:${LD_LIBRARY_PATH:-}" "${prefix}/bin/openssl" version -a
  } 2>&1 | tee "$log_file"
}

main "$@"
