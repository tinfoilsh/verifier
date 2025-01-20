package attestation

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

type PredicateType string

const (
	AWSNitroEnclaveV1 PredicateType = "https://tinfoil.sh/predicate/aws-nitro-enclave/v1"
)

var (
	ErrFormatMismatch      = errors.New("attestation format mismatch")
	ErrMeasurementMismatch = errors.New("measurement mismatch")
)

type Measurement struct {
	Type      PredicateType
	Registers []string
}

// Fingerprint computes the SHA-256 hash of all measurements
func (m *Measurement) Fingerprint() string {
	all := string(m.Type) + strings.Join(m.Registers, "")
	return fmt.Sprintf("%x", sha256.Sum256([]byte(all)))
}

func (m *Measurement) Equals(other *Measurement) error {
	if m.Type != other.Type {
		return ErrFormatMismatch
	}
	if len(m.Registers) != len(other.Registers) || !slices.Equal(m.Registers, other.Registers) {
		return ErrMeasurementMismatch
	}

	return nil
}

// Document represents an attestation document
type Document struct {
	Format PredicateType `json:"format"`
	Body   string        `json:"body"`
}

// Verify checks the attestation document against its trust root and returns the inner measurements
func (d *Document) Verify() (*Measurement, []byte, error) {
	switch d.Format {
	case AWSNitroEnclaveV1:
		return verifyNitroAttestation(d.Body)
	default:
		return nil, nil, fmt.Errorf("unsupported attestation format: %s", d.Format)
	}
}

// VerifyAttestationJSON verifies an attestation document in JSON format and returns the inner measurements
func VerifyAttestationJSON(j []byte) (*Measurement, []byte, error) {
	var doc Document
	err := json.Unmarshal(j, &doc)
	if err != nil {
		return nil, nil, err
	}

	return doc.Verify()
}

// CertFP gets the SHA256 fingerprint of a certificate
func CertFP(c tls.ConnectionState) []byte {
	fp := sha256.Sum256(c.PeerCertificates[0].Raw)
	return fp[:]
}
