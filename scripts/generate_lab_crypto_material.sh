#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
OPENSSL="${REPO_ROOT}/.local/openssl-3.5.7/bin/openssl"
MATERIAL_DIR="${REPO_ROOT}/.local/pqtrust-crypto"

CA_KEY="${MATERIAL_DIR}/lab_ca_p256.key.pem"
CA_CERT="${MATERIAL_DIR}/lab_ca_p256.cert.pem"
SERVER_KEY="${MATERIAL_DIR}/server_p256.key.pem"
SERVER_CSR="${MATERIAL_DIR}/server_p256.csr.pem"
SERVER_CERT="${MATERIAL_DIR}/server_p256.cert.pem"
SERVER_EXT="${MATERIAL_DIR}/server_cert.ext"
MLDSA65_PRIVATE="${MATERIAL_DIR}/mldsa65.private.pem"
MLDSA65_PUBLIC="${MATERIAL_DIR}/mldsa65.public.pem"
MLDSA87_PRIVATE="${MATERIAL_DIR}/mldsa87.private.pem"
MLDSA87_PUBLIC="${MATERIAL_DIR}/mldsa87.public.pem"

files=(
  "${CA_KEY}" "${CA_CERT}" "${SERVER_KEY}" "${SERVER_CERT}" "${SERVER_EXT}"
  "${MLDSA65_PRIVATE}" "${MLDSA65_PUBLIC}" "${MLDSA87_PRIVATE}" "${MLDSA87_PUBLIC}"
)

if [[ ! -x "${OPENSSL}" ]]; then
  echo "repository-local OpenSSL executable is missing: ${OPENSSL}" >&2
  exit 1
fi

verify_material() {
  "${OPENSSL}" verify -CAfile "${CA_CERT}" "${SERVER_CERT}" >/dev/null
  "${OPENSSL}" x509 -in "${SERVER_CERT}" -noout -ext subjectAltName | grep -q "DNS:localhost"
  "${OPENSSL}" x509 -in "${SERVER_CERT}" -noout -ext subjectAltName | grep -q "IP Address:127.0.0.1"
  "${OPENSSL}" pkey -in "${MLDSA65_PRIVATE}" -noout >/dev/null
  "${OPENSSL}" pkey -pubin -in "${MLDSA65_PUBLIC}" -noout >/dev/null
  "${OPENSSL}" pkey -in "${MLDSA87_PRIVATE}" -noout >/dev/null
  "${OPENSSL}" pkey -pubin -in "${MLDSA87_PUBLIC}" -noout >/dev/null

  local msg sig
  msg="$(mktemp)"
  sig="$(mktemp)"
  printf 'PQTrust laboratory ML-DSA verification\n' > "${msg}"
  "${OPENSSL}" pkeyutl -sign -rawin -inkey "${MLDSA65_PRIVATE}" -in "${msg}" -out "${sig}" >/dev/null
  "${OPENSSL}" pkeyutl -verify -rawin -pubin -inkey "${MLDSA65_PUBLIC}" -in "${msg}" -sigfile "${sig}" >/dev/null
  "${OPENSSL}" pkeyutl -sign -rawin -inkey "${MLDSA87_PRIVATE}" -in "${msg}" -out "${sig}" >/dev/null
  "${OPENSSL}" pkeyutl -verify -rawin -pubin -inkey "${MLDSA87_PUBLIC}" -in "${msg}" -sigfile "${sig}" >/dev/null
  rm -f "${msg}" "${sig}"
}

if [[ -d "${MATERIAL_DIR}" ]]; then
  complete=true
  for file in "${files[@]}"; do
    [[ -f "${file}" ]] || complete=false
  done
  if [[ "${complete}" == "true" ]]; then
    verify_material
    echo "existing laboratory cryptographic material verified"
    exit 0
  fi
  echo "partial laboratory cryptographic material exists; refusing to mix old and new files" >&2
  exit 1
fi

tmp_dir="${MATERIAL_DIR}.tmp.$$"
mkdir -p "${tmp_dir}"
chmod 700 "${tmp_dir}"
trap 'rm -rf "${tmp_dir}"' EXIT

CA_KEY="${tmp_dir}/lab_ca_p256.key.pem"
CA_CERT="${tmp_dir}/lab_ca_p256.cert.pem"
SERVER_KEY="${tmp_dir}/server_p256.key.pem"
SERVER_CSR="${tmp_dir}/server_p256.csr.pem"
SERVER_CERT="${tmp_dir}/server_p256.cert.pem"
SERVER_EXT="${tmp_dir}/server_cert.ext"
MLDSA65_PRIVATE="${tmp_dir}/mldsa65.private.pem"
MLDSA65_PUBLIC="${tmp_dir}/mldsa65.public.pem"
MLDSA87_PRIVATE="${tmp_dir}/mldsa87.private.pem"
MLDSA87_PUBLIC="${tmp_dir}/mldsa87.public.pem"

"${OPENSSL}" ecparam -name prime256v1 -genkey -noout -out "${CA_KEY}"
chmod 600 "${CA_KEY}"
"${OPENSSL}" req -new -x509 -sha256 -days 3650 \
  -key "${CA_KEY}" -out "${CA_CERT}" \
  -subj "/CN=PQTrust Laboratory P-256 CA/O=PQTrust-Agent Laboratory"

"${OPENSSL}" ecparam -name prime256v1 -genkey -noout -out "${SERVER_KEY}"
chmod 600 "${SERVER_KEY}"
"${OPENSSL}" req -new -sha256 -key "${SERVER_KEY}" -out "${SERVER_CSR}" \
  -subj "/CN=localhost/O=PQTrust-Agent Laboratory"
cat > "${SERVER_EXT}" <<'EOF'
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
EOF
"${OPENSSL}" x509 -req -sha256 -days 3650 -in "${SERVER_CSR}" \
  -CA "${CA_CERT}" -CAkey "${CA_KEY}" -CAcreateserial \
  -out "${SERVER_CERT}" -extfile "${SERVER_EXT}"

"${OPENSSL}" genpkey -algorithm ML-DSA-65 -out "${MLDSA65_PRIVATE}"
chmod 600 "${MLDSA65_PRIVATE}"
"${OPENSSL}" pkey -in "${MLDSA65_PRIVATE}" -pubout -out "${MLDSA65_PUBLIC}"
"${OPENSSL}" genpkey -algorithm ML-DSA-87 -out "${MLDSA87_PRIVATE}"
chmod 600 "${MLDSA87_PRIVATE}"
"${OPENSSL}" pkey -in "${MLDSA87_PRIVATE}" -pubout -out "${MLDSA87_PUBLIC}"

MATERIAL_DIR="${tmp_dir}" verify_material
rm -f "${tmp_dir}/server_p256.csr.pem" "${tmp_dir}/lab_ca_p256.cert.srl"
mv "${tmp_dir}" "${REPO_ROOT}/.local/pqtrust-crypto"
trap - EXIT
echo "generated laboratory-only cryptographic material under .local/pqtrust-crypto"
