package attestation

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/blocky/nitrite"
)

type Attestation struct {
	Measurements []string
}

type AttestationResponse struct {
	Version     string `json:"version"`
	Attestation struct {
		Format string `json:"format"`
		Body   string `json:"body"`
	} `json:"attestation"`
}

func ParseAttestation(j string) (*Attestation, error) {
	var a AttestationResponse
	if err := json.Unmarshal([]byte(j), &a); err != nil {
		return nil, err
	}

	switch a.Attestation.Format {
	case "awsnitro":
		return parseAWSNitroAttestation(a.Attestation.Body)
	default:
		return nil, errors.New("unsupported attestation format")
	}
}

func parseAWSNitroAttestation(attestationDoc string) (*Attestation, error) {
	attDocBytes, err := base64.StdEncoding.DecodeString(attestationDoc)
	if err != nil {
		return nil, err
	}
	attestedResult, err := nitrite.Verify(attDocBytes, nitrite.VerifyOptions{})
	if err != nil {
		return nil, err
	}

	pcrs := MeasurementFromDoc(attestedResult.Document)
	return &Attestation{
		Measurements: []string{
			pcrs.PCR0,
			pcrs.PCR1,
			pcrs.PCR2,
		},
	}, nil
}
