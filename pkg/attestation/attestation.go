package attestation

import (
	"encoding/json"
	"errors"
	"slices"
)

type MeasurementType string

const (
	AWSNitroEnclaveV1 MeasurementType = "https://tinfoil.sh/predicate/aws-nitro-enclave/v1"
)

var (
	ErrUnsupportedAttestationFormat = errors.New("unsupported attestation format")
	ErrFormatMismatch               = errors.New("attestation format mismatch")
	ErrMeasurementMismatch          = errors.New("measurement mismatch")
)

type Measurement struct {
	Type      MeasurementType
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
	Version     string `json:"version"` // Enclave's self-reported release version
	Attestation struct {
		Format MeasurementType `json:"format"`
		Body   string          `json:"body"`
	} `json:"attestation"`
}

func ParseAttestation(attestationDocJSON []byte) (*Measurement, error) {
	var d Document
	if err := json.Unmarshal(attestationDocJSON, &d); err != nil {
		return nil, err
	}

	switch d.Attestation.Format {
	case AWSNitroEnclaveV1:
		return parseAWSNitroAttestation(d.Attestation.Body)
	default:
		return nil, ErrUnsupportedAttestationFormat
	}
}
