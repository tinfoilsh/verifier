//go:build !wasm
// +build !wasm

package client

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/tinfoilsh/verifier/attestation"
)

// enclaveValidPubKey checks if the public key covered by the attestation matches the public key of the enclave
func enclaveValidPubKey(enclave string, enclaveVerification *attestation.Verification) error {
	// Get cert from TLS connection
	var addr string
	if strings.Contains(enclave, ":") {
		// Enclave already has a port specified
		addr = enclave
	} else {
		// Append default HTTPS port
		addr = enclave + ":443"
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to enclave: %v", err)
	}
	defer conn.Close()
	certFP, err := attestation.ConnectionCertFP(conn.ConnectionState())
	if err != nil {
		return fmt.Errorf("failed to get certificate fingerprint: %v", err)
	}

	// Check if the certificate fingerprint matches the one in the verification
	if certFP != enclaveVerification.TLSPublicKeyFP {
		return fmt.Errorf("certificate fingerprint mismatch: expected %s, got %s", enclaveVerification.TLSPublicKeyFP, certFP)
	}

	return nil
}
