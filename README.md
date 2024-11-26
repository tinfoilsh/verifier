# Tinfoil Verifier

## Online In-Browser Verification

https://tinfoilanalytics.github.io/verifier/

## Local Verification

```bash
go run cmd/main.go \
  -attestation https://inference.tinfoil.sh/.well-known/nitro-attestation \
  -repo tinfoilanalytics/nitro-private-inference-image \
  -digest 6d87ba0d92af58c1d740b8aa7d2c3521d8cff96a520502a8b748c3a744ae015f
```
