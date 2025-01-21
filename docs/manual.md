# Source Code Attestation Verification

### 1. Download enclave image

```bash
export REPO=tinfoilanalytics/nitro-enclave-build-demo
oras pull "ghcr.io/$REPO:v0.0.12"
```

### 2. Verify Attestation

#### 2.1. Download Attestation Document

```bash
DIGEST="sha256:$(sha256sum enclave.eif | cut -d ' ' -f 1)"
curl -sL "https://api.github.com/repos/$REPO/attestations/$DIGEST" | jq -r ".attestations[0].bundle" > attestation.jsonl
```

#### 2.2. Verify Attestation with [cosign](https://github.com/sigstore/cosign)

```bash
cosign verify-blob-attestation \
  --new-bundle-format \
  --bundle attestation.jsonl \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp="^https://github.com/$REPO/.github/workflows/release.yml.?" \
  enclave.eif
```

### 3. Extract PCR measurement predicate

```bash
jq -r ".dsseEnvelope.payload" attestation.jsonl | base64 -d | jq -r ".predicate"
```
