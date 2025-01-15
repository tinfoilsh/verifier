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

// VerifyAttestation validates the attestation document and returns the inner measurement
func VerifyAttestation(attestationDocJSON []byte) (*Measurement, error) {
	var d Document
	if err := json.Unmarshal(attestationDocJSON, &d); err != nil {
		return nil, err
	}

	switch d.Format {
	case AWSNitroEnclaveV1:
		return verifyNitroAttestation(d.Body)
	default:
		return nil, ErrUnsupportedAttestationFormat
	}
}
