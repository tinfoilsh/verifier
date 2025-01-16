# Tinfoil Verifier

## Online In-Browser Verification

https://tinfoilanalytics.github.io/verifier

## Local Verification

```bash
go run cmd/main.go \
  -u https://inference-enclave.tinfoil.sh/.well-known/tinfoil-attestation \
  -r tinfoilanalytics/nitro-enclave-build-demo
```
