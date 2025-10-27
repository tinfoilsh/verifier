package client

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinfoilsh/verifier/attestation"
)

func TestVerify(t *testing.T) {
	tests := []struct {
		enclave string
		repo    string
	}{
		{"deepseek-r1-0528.inf3.tinfoil.sh", "tinfoilsh/confidential-deepseek-r1-0528"},
		{"inference.tinfoil.sh", "tinfoilsh/confidential-inference-proxy"},
		{"llama3-3-70b.model.tinfoil.sh", "tinfoilsh/confidential-llama3-3-70b"},
	}

	for _, test := range tests {
		t.Run(test.enclave, func(t *testing.T) {
			client := NewSecureClient(test.enclave, test.repo)
			_, err := client.Verify()
			assert.NoError(t, err)
		})
	}
}

func TestClientGroundTruthJSON(t *testing.T) {
	codeMeasurement := &attestation.Measurement{
		Type:      attestation.SnpTdxMultiPlatformV1,
		Registers: []string{"a", "b"},
	}
	enclaveMeasurement := &attestation.Measurement{
		Type:      attestation.TdxGuestV1,
		Registers: []string{"a"},
	}

	gt := &GroundTruth{
		TLSPublicKey:       "pubkey",
		HPKEPublicKey:      "hpkekey",
		Digest:             "feabcd",
		CodeMeasurement:    codeMeasurement,
		EnclaveMeasurement: enclaveMeasurement,
	}
	client := &SecureClient{
		groundTruth: gt,
	}

	encoded, err := client.GroundTruthJSON()
	assert.NoError(t, err)

	// Decode and compare
	var gt2 GroundTruth
	assert.NoError(t, json.Unmarshal([]byte(encoded), &gt2))
	assert.Equal(t, gt, &gt2)
}
