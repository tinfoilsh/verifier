package models

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/blocky/nitrite"
)

type Attestation struct {
	Measurements []string
}

type Manifest struct {
	Version     string `json:"version"`
	Attestation struct {
		Format string `json:"format"`
		Body   string `json:"body"`
	} `json:"attestation"`
}

func ParseManifest(j string) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal([]byte(j), &m); err != nil {
		return nil, err
	}
	return &m, nil
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

func (m *Manifest) GetAttestation() (*Attestation, error) {
	switch m.Attestation.Format {
	case "awsnitro":
		return parseAWSNitroAttestation(m.Attestation.Body)
	default:
		return nil, errors.New("unsupported attestation format")
	}
}
