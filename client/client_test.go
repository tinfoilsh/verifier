package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
