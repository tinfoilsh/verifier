# Tinfoil Verifier

## Online In-Browser Verification

https://tinfoilanalytics.github.io/verifier/

## Local Verification

```bash
go run cmd/main.go \
  -attestation https://inference-demo.tinfoil.sh/.well-known/nitro-attestation \
  -repo tinfoilanalytics/nitro-private-inference-image \
  -digest c6a7de8bd85b58d958a64ee244453fa49165fa35864c8a5af333ee65b922cc8d
```
