# Tinfoil Verifier

Portable remote-attestation verifier & secure HTTP client for enclave-backed services.

[![Build Status](https://github.com/tinfoilsh/verifier/workflows/Run%20tests/badge.svg)](https://github.com/tinfoilsh/verifier/actions)

## Overview
Tinfoil Verifier is a Go library that verifies the integrity of remote enclaves (AMD SEV-SNP & Intel TDX) and binds that verification to TLS connections. It also ships a drop-in secure `http.Client` that performs attestation transparently.

## Features
- **Hardware-rooted remote attestation** for AMD SEV-SNP & Intel TDX
- **Self-contained** with no external attestation service
- **Secure HTTP client** with automatic TLS certificate pinning
- **Sigstore integration** for code provenance verification
- **Attested HPKE public keys** for use with [EHBP](https://docs.tinfoil.sh/resources/ehbp) clients
- **WASM build** for browser/Node.js environments
- **Swift bindings** via gomobile for iOS/macOS integration  

## Installation
```bash
go get github.com/tinfoilsh/verifier@latest
```

> **Note**  Until `go-sev-guest` upstreams a required feature, add the temporary replace directive:
> ```bash
> go mod edit -replace github.com/google/go-sev-guest=github.com/tinfoilsh/go-sev-guest@v0.0.0-20250704193550-c725e6216008
> ```

## Quick Start
```go
import "github.com/tinfoilsh/verifier/client"

// 1. Create a client
tinfoilClient := client.NewSecureClient("enclave.example.com", "org/repo")

// 2. Perform HTTP requests – attestation happens automatically
resp, err := tinfoilClient.Get("/api/data", nil)
if err != nil {
    log.Fatal(err)
}
log.Printf("Status: %s, Body: %s", resp.Status, string(resp.Body))
```

To verify manually and expose the verification state:
```go
groundTruth, err := tinfoilClient.Verify()
if err != nil {
    log.Fatal(err)
}
// Access verified measurements and keys
log.Printf("TLS Cert Fingerprint: %s", groundTruth.TLSPublicKey)
log.Printf("HPKE Public Key: %s", groundTruth.HPKEPublicKey)
```

## Secure HTTP Client
The `client` package wraps `net/http` and adds:
1. **Attestation gate** – the first request verifies the enclave.
2. **TLS pinning** – the enclave-generated certificate fingerprint is pinned for the session.
3. **Round-tripping helpers** – convenience `Get`, `Post` methods.

```go
headers := map[string]string{"Content-Type": "application/json"}
body    := []byte(`{"key": "value"}`)

resp, err := tinfoilClient.Post("/api/submit", headers, body)
```

For advanced usage retrieve the underlying `*http.Client`:
```go
httpClient, err := tinfoilClient.HTTPClient()
```

## Remote Attestation
Tinfoil Verifier currently supports two platforms:

| Platform       | Technique                                | Docs                                                  |
|----------------|------------------------------------------|-------------------------------------------------------|
| **AMD SEV-SNP**| VCEK certificates & SNP report validation | [AMD Spec](https://www.amd.com/en/developer/sev.html)  |
| **Intel TDX** | TDX quote validation & TD report checks   | [Intel Guide](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html) |

### Verification Flow
```mermaid
sequenceDiagram
    participant Client
    participant Enclave
    participant TrustRoot
    participant Sigstore

    Client->>Enclave: Request attestation
    Enclave-->>Client: Report + TLS pubkey
    Client->>TrustRoot: Verify signature chain
    Client->>Sigstore: Fetch reference measurement
    Client->>Client: Compare measurements & pin cert
```

> **Note:** The [Bundled Verification](#bundled-verification) flow aggregates all these steps into a single request via Tinfoil ATC.

### Bundled Verification

You can fetch a pre-aggregated bundle from Tinfoil ATC (air-traffic-control) that contains all verification data in a single request:

> **Note:** Bundled verification currently supports AMD SEV-SNP only. Intel TDX support is coming soon.

```go
// Single-request verification via ATC
groundTruthJSON, err := client.VerifyFromATCJSON("org/repo", nil)
if err != nil {
    log.Fatal(err)
}

// Or via your own bundle proxy URL
groundTruthJSON, err := client.VerifyFromATCURLJSON("https://proxy.example.com", "org/repo", nil)
```

If you've already fetched the bundle yourself:
```go
groundTruthJSON, err := client.VerifyFromBundleJSON(bundleJSON, "org/repo", nil)
```


## JavaScript / TypeScript / WASM

### JavaScript / TypeScript SDK

For production JavaScript/TypeScript applications, use the [tinfoil-js](https://github.com/tinfoilsh/tinfoil-js) package, which provides:
- OpenAI-compatible API with built-in verification
- Native JavaScript verification implementation
- EHBP (Encrypted HTTP Body Protocol) for end-to-end encryption
- Support for browsers, Node.js 20+, Deno, Bun, and Cloudflare Workers
- Comprehensive verification reporting with step-by-step diagnostics

```bash
npm install tinfoil
```

See the [tinfoil-js documentation](https://github.com/tinfoilsh/tinfoil-js) for usage examples.

### Direct WASM Usage

For custom integrations requiring the Go verification logic in browsers, you can use the WASM verifier directly. Built from the same Go source code, it's compiled to WebAssembly to run natively in browsers.

When new versions are tagged, our GitHub Actions workflow automatically:
1. Compiles the Go verification logic to WebAssembly
2. Generates versioned WASM files with integrity guarantees
3. Deploys them to GitHub Pages for secure, cached distribution
4. Updates version tags so clients always load the correct module


The WASM verifier is hosted at:
```
https://tinfoilsh.github.io/verifier/tinfoil-verifier.wasm
```

Include the Go WASM runtime and load the verifier:

```html
<script src="wasm_exec.js"></script>

<script>
// Load the WASM verifier
const go = new Go();
WebAssembly.instantiateStreaming(
  fetch("https://tinfoilsh.github.io/verifier/tinfoil-verifier.wasm"),
  go.importObject
).then((result) => {
  go.run(result.instance);

  // Complete end-to-end verification (recommended)
  verify("inference.example.com", "tinfoilsh/confidential-llama-qwen")
    .then(groundTruthJSON => {
      const groundTruth = JSON.parse(groundTruthJSON);
      console.log("TLS Cert Fingerprint:", groundTruth.tls_public_key);
      console.log("HPKE Public Key:", groundTruth.hpke_public_key);
      console.log("Verification successful!");
    })
    .catch(error => {
      console.error("Verification failed:", error);
    });
});
</script>
```


## Auditing the Verification Code 
1. **Certificate chain** – see [`/attestation/genoa_cert_chain.pem`](attestation/genoa_cert_chain.pem)
2. **Attestation verification** – platform-specific attestation logic:
   - [`/attestation/sev.go`](attestation/sev.go) – AMD SEV-SNP attestation
   - [`/attestation/tdx.go`](attestation/tdx.go) – Intel TDX attestation
3. **Measurement comparison** – see [`Measurement.Equals()`](attestation/attestation.go#L186) in [`/attestation/attestation.go`](attestation/attestation.go)
4. **Code provenance verification** – Sigstore/Rekor integration in [`/sigstore/sigstore.go`](sigstore/sigstore.go)
5. **End-to-end verification flow** – [`client.Verify()`](client/client.go#L142) in [`/client/client.go`](client/client.go)

## Reporting Vulnerabilities

Please report security vulnerabilities by either:

- Emailing [security@tinfoil.sh](mailto:security@tinfoil.sh)

- Opening an issue on GitHub on this repository

We aim to respond to (legitimate) security reports within 24 hours.
