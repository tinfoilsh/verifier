# Tinfoil Verifier

Tinfoil's client-side portable remote attestation verifier.

[![Build Status](https://github.com/tinfoilanalytics/verifier/workflows/Run%20tests/badge.svg)](https://github.com/tinfoilanalytics/verifier/actions)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Getting Started

### Online Verification

#### In Browser
Access the browser-based verifier at https://tinfoilanalytics.github.io/verifier

#### CLI

```bash
go run cmd/manual/main.go \
  -e inference-enclave.tinfoil.sh \
  -r tinfoilanalytics/nitro-enclave-build-demo
```
