#!/bin/bash
# gen_corpus.sh - mint realistic DER seeds for the libksba harnesses with openssl.
# Offline only: a throwaway mini-CA (conf/ca.cnf) signs a leaf, a CRL and an OCSP
# response. Output: corpus/{cert,crl,cms,ocsp}/*.der
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
cd "${SCRIPT_DIR}"

CADIR="$(mktemp -d)"
export CADIR
CONF="${SCRIPT_DIR}/conf/ca.cnf"
trap 'rm -rf "${CADIR}"' EXIT

log() { echo "[*] $*"; }
ok()  { echo "[+] $*"; }

mkdir -p corpus/cert corpus/crl corpus/cms corpus/ocsp
mkdir -p "${CADIR}/newcerts"
: > "${CADIR}/index.txt"
echo 1000 > "${CADIR}/serial"
echo 1000 > "${CADIR}/crlnumber"

log "CA + leaf..."
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "${CADIR}/ca.key" -out "${CADIR}/ca.crt" \
    -subj "/CN=Fuzz Root CA/O=djnn/C=FR" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

openssl req -newkey rsa:2048 -nodes \
    -keyout "${CADIR}/leaf.key" -out "${CADIR}/leaf.csr" \
    -subj "/CN=leaf.example/O=djnn/C=FR" 2>/dev/null

openssl ca -batch -config "${CONF}" -notext \
    -in "${CADIR}/leaf.csr" -out "${CADIR}/leaf.crt" 2>/dev/null

openssl x509 -in "${CADIR}/ca.crt"   -outform DER -out corpus/cert/ca.der
openssl x509 -in "${CADIR}/leaf.crt" -outform DER -out corpus/cert/leaf.der
ok "cert seeds"

log "CRL (empty + one revoked entry)..."
openssl ca -batch -config "${CONF}" -gencrl -out "${CADIR}/crl-empty.pem" 2>/dev/null
openssl crl -in "${CADIR}/crl-empty.pem" -outform DER -out corpus/crl/empty.der
openssl ca -batch -config "${CONF}" -revoke "${CADIR}/leaf.crt" -crl_reason keyCompromise 2>/dev/null
openssl ca -batch -config "${CONF}" -gencrl -out "${CADIR}/crl-revoked.pem" 2>/dev/null
openssl crl -in "${CADIR}/crl-revoked.pem" -outform DER -out corpus/crl/revoked.der
ok "CRL seeds"

log "CMS / PKCS#7 signed..."
echo "fuzz me" > "${CADIR}/msg.txt"
openssl cms -sign -binary -nodetach -outform DER \
    -signer "${CADIR}/leaf.crt" -inkey "${CADIR}/leaf.key" \
    -in "${CADIR}/msg.txt" -out corpus/cms/signed.der 2>/dev/null
ok "CMS seed"

log "OCSP response (offline responder)..."
if openssl ocsp -issuer "${CADIR}/ca.crt" -cert "${CADIR}/leaf.crt" \
        -reqout "${CADIR}/req.der" -no_nonce 2>/dev/null \
   && openssl ocsp -index "${CADIR}/index.txt" -CA "${CADIR}/ca.crt" \
        -rsigner "${CADIR}/ca.crt" -rkey "${CADIR}/ca.key" \
        -reqin "${CADIR}/req.der" -respout corpus/ocsp/resp.der -no_nonce 2>/dev/null; then
    ok "OCSP seed"
else
    echo "[!] OCSP seed skipped (openssl ocsp responder unavailable); seeding with cert DER"
    cp corpus/cert/leaf.der corpus/ocsp/leaf.der
fi

echo
ok "corpus ready:"
find corpus -type f -printf '    %p (%s bytes)\n' | sort
