//go:build js && wasm
// +build js,wasm

package client

import (
	"fmt"

	"github.com/tinfoilsh/verifier/attestation"
)

// enclaveValidPubKey is disabled in WASM builds since tls.Dial is not available
func enclaveValidPubKey(enclave string, enclaveVerification *attestation.Verification) error {
	fmt.Printf("Warning: TLS certificate validation for enclave %s is disabled in WASM build\n", enclave)
	return nil
}
