package attestation

import (
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// CertVerificationResult contains the extracted values from certificate verification
type CertVerificationResult struct {
	HPKEPublicKey   string
	AttestationHash string
	DNSNames        []string
}

// VerifyCertificate verifies an enclave TLS certificate against expected values.
// It checks that:
// 1. Certificate is valid for the expected domain
// 2. Certificate SANs contain the correct HPKE key
// 3. Certificate SANs contain the correct attestation hash
func VerifyCertificate(certPEM string, expectedDomain string, attestationDoc *Document, expectedHPKEKey string) (*CertVerificationResult, error) {
	// 1. Parse PEM certificate
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// 2. Extract SANs (DNS names)
	sans := cert.DNSNames
	if len(sans) == 0 {
		return nil, fmt.Errorf("certificate has no Subject Alternative Names")
	}

	// 3. Verify domain
	if err := cert.VerifyHostname(expectedDomain); err != nil {
		return nil, fmt.Errorf("certificate not valid for domain: %s. SANs: %v", expectedDomain, sans)
	}

	// 4. Extract and verify HPKE key
	hpkeSANs := filterSANs(sans, ".hpke.")
	if len(hpkeSANs) == 0 {
		return nil, fmt.Errorf("certificate SANs do not contain HPKE key")
	}

	hpkeKeyBytes, err := decodeDomains(hpkeSANs, "hpke")
	if err != nil {
		return nil, fmt.Errorf("failed to decode HPKE key from SANs: %v", err)
	}

	hpkePublicKey := fmt.Sprintf("%x", hpkeKeyBytes)
	if hpkePublicKey != expectedHPKEKey {
		return nil, fmt.Errorf("HPKE key mismatch: certificate has %s, expected %s", hpkePublicKey, expectedHPKEKey)
	}

	// 5. Extract and verify attestation hash
	hattSANs := filterSANs(sans, ".hatt.")
	if len(hattSANs) == 0 {
		return nil, fmt.Errorf("certificate SANs do not contain attestation hash")
	}

	hashBytes, err := decodeDomains(hattSANs, "hatt")
	if err != nil {
		return nil, fmt.Errorf("failed to decode attestation hash from SANs: %v", err)
	}

	// The hash is stored as the hex string bytes
	certAttestationHash := string(hashBytes)
	computedHash := attestationDoc.Hash()

	if certAttestationHash != computedHash {
		return nil, fmt.Errorf("attestation hash mismatch: certificate has %s, computed %s", certAttestationHash, computedHash)
	}

	return &CertVerificationResult{
		HPKEPublicKey:   hpkePublicKey,
		AttestationHash: computedHash,
		DNSNames:        sans,
	}, nil
}

// filterSANs returns SANs containing the given substring
func filterSANs(sans []string, substring string) []string {
	var filtered []string
	for _, san := range sans {
		if strings.Contains(san, substring) {
			filtered = append(filtered, san)
		}
	}
	return filtered
}

// decodeDomains decodes dcode-encoded data from certificate SANs.
// Format: NN<base32-chunk>.<prefix>.<domain> where NN is chunk index.
func decodeDomains(domains []string, prefix string) ([]byte, error) {
	pattern := "." + prefix + "."

	// Filter and sort domains by index
	type indexedChunk struct {
		index int
		chunk string
	}
	var chunks []indexedChunk

	for _, d := range domains {
		if !strings.Contains(d, pattern) {
			continue
		}

		// Get first part before the first dot
		parts := strings.Split(d, ".")
		if len(parts) == 0 {
			continue
		}

		firstPart := parts[0]
		if len(firstPart) < 2 {
			continue
		}

		// Parse the 2-digit index prefix
		idx, err := strconv.Atoi(firstPart[:2])
		if err != nil {
			continue
		}

		// Get the base32 chunk (everything after the 2-digit index)
		chunk := firstPart[2:]
		chunks = append(chunks, indexedChunk{index: idx, chunk: chunk})
	}

	if len(chunks) == 0 {
		return nil, fmt.Errorf("no domains with prefix: %s", prefix)
	}

	// Sort by index
	sort.Slice(chunks, func(i, j int) bool {
		return chunks[i].index < chunks[j].index
	})

	// Concatenate chunks
	var combined strings.Builder
	for _, c := range chunks {
		combined.WriteString(c.chunk)
	}

	// Base32 decode (standard alphabet, no padding)
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	decoded, err := decoder.DecodeString(strings.ToUpper(combined.String()))
	if err != nil {
		return nil, fmt.Errorf("base32 decode error: %v", err)
	}

	return decoded, nil
}
