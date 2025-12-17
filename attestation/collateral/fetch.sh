#!/bin/bash
# Fetches Intel PCS collateral for TDX attestation verification
# Run this script periodically to update embedded collateral

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BASE_URL_TDX="https://api.trustedservices.intel.com/tdx/certification/v4"
BASE_URL_CERTS="https://certificates.trustedservices.intel.com"

echo "Fetching QE Identity..."
response=$(curl -sf -D - "$BASE_URL_TDX/qe/identity")
echo "$response" | sed -n '/^{/,$p' > qe_identity.json
echo "$response" | grep -i "^SGX-Enclave-Identity-Issuer-Chain:" | sed 's/^[^:]*: //' | tr -d '\r' > qe_identity_chain.txt

echo "Fetching Root CA CRL..."
curl -sf "$BASE_URL_CERTS/IntelSGXRootCA.der" -o root_ca.crl

echo "Fetching PCK CRL (processor CA)..."
response=$(curl -sf -D - "$BASE_URL_CERTS/pck-crl?ca=processor&encoding=der" -o pck_crl_processor.crl)
echo "$response" | grep -i "^Sgx-Pck-Crl-Issuer-Chain:" | sed 's/^[^:]*: //' | tr -d '\r' > pck_crl_processor_chain.txt

echo "Fetching PCK CRL (platform CA)..."
response=$(curl -sf -D - "$BASE_URL_CERTS/pck-crl?ca=platform&encoding=der" -o pck_crl_platform.crl)
echo "$response" | grep -i "^Sgx-Pck-Crl-Issuer-Chain:" | sed 's/^[^:]*: //' | tr -d '\r' > pck_crl_platform_chain.txt

# Known FMSPCs for TDX platforms
# Add more FMSPCs here as needed for your deployments
FMSPCS=(
    "00a06d080000"
    "90c06f000000"
)

for fmspc in "${FMSPCS[@]}"; do
    echo "Fetching TCB Info for FMSPC $fmspc..."
    response=$(curl -sf -D - "$BASE_URL_TDX/tcb?fmspc=$fmspc")
    echo "$response" | sed -n '/^{/,$p' > "tcb_info_${fmspc}.json"
    echo "$response" | grep -i "^TCB-Info-Issuer-Chain:" | sed 's/^[^:]*: //' | tr -d '\r' > "tcb_info_${fmspc}_chain.txt"
done

echo ""
echo "Done. Collateral files updated."
echo ""
echo "QE Identity tcbEvaluationDataNumber:"
grep -o '"tcbEvaluationDataNumber":[0-9]*' qe_identity.json | head -1 || true

for fmspc in "${FMSPCS[@]}"; do
    if [ -s "tcb_info_${fmspc}.json" ]; then
        echo "TCB Info ($fmspc) tcbEvaluationDataNumber:"
        grep -o '"tcbEvaluationDataNumber":[0-9]*' "tcb_info_${fmspc}.json" | head -1 || true
    fi
done
