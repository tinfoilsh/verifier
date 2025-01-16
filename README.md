# Tinfoil Verifier

## Online In-Browser Verification

https://tinfoilanalytics.github.io/verifier/

## Local Verification

```bash
go run cmd/main.go \
  -u https://inference-enclave.tinfoil.sh/.well-known/tinfoil-attestation \
  -r tinfoilanalytics/nitro-enclave-build-demo \
  -d 55b9a80c11415508cf178f1c94c6c8837a21a8bbae51130234d93404dc922baf
```
