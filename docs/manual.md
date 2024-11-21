# Verify Enclave Attestation

### 1. Download enclave image

```bash
curl -L https://static.tinfoil.sh/tinfoil-enclave-ollama-v0.0.4.eif -o tinfoil-enclave.eif
```

### 2. Verify Attestation

#### 2.1. Download Attestation Document

```bash
DIGEST="sha256:$(sha256sum tinfoil-enclave.eif | cut -d ' ' -f 1)"
curl -sL "https://api.github.com/repos/tinfoilanalytics/nitro-private-inference-image/attestations/$DIGEST" | jq -r ".attestations[0].bundle" > attestation.jsonl
```

#### 2.2. Verify Attestation with [cosign](https://github.com/sigstore/cosign)

```bash
cosign verify-blob-attestation \
  --new-bundle-format \
  --bundle attestation.jsonl \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp="^https://github.com/tinfoilanalytics/nitro-private-inference-image/.github/workflows/release.yml.?" \
  tinfoil-enclave.eif
```

### 3. Extract PCR measurement predicate

```bash
jq -r ".dsseEnvelope.payload" attestation.jsonl | base64 -d | jq -r ".predicate"
```
