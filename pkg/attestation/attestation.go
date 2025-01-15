package attestation

import (
	"encoding/json"
	"errors"
	"slices"
)

type PredicateType string

const (
	AWSNitroEnclaveV1 PredicateType = "https://tinfoil.sh/predicate/aws-nitro-enclave/v1"
)

var (
	ErrUnsupportedAttestationFormat = errors.New("unsupported attestation format")
	ErrFormatMismatch               = errors.New("attestation format mismatch")
	ErrMeasurementMismatch          = errors.New("measurement mismatch")
)

type Measurement struct {
	Type      PredicateType
	Registers []string
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
	Version string        `json:"version"` // Enclave's self-reported release version
	Format  PredicateType `json:"format"`
	Body    string        `json:"body"`
}

// Verify checks the attestation document against its trust root and returns the inner measurements
func (d *Document) Verify() (*Measurement, []byte, error) {
	switch d.Format {
	case AWSNitroEnclaveV1:
		return verifyNitroAttestation(d.Body)
	default:
		return nil, nil, ErrUnsupportedAttestationFormat
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
