package attestation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMeasurementEquals(t *testing.T) {
	tests := []struct {
		name    string
		m1      *Measurement
		m2      *Measurement
		wantErr error
	}{
		{
			name: "same measurements",
			m1: &Measurement{
				Type:      AWSNitroEnclaveV1,
				Registers: []string{"reg1", "reg2"},
			},
			m2: &Measurement{
				Type:      AWSNitroEnclaveV1,
				Registers: []string{"reg1", "reg2"},
			},
			wantErr: nil,
		},
		{
			name: "different types",
			m1: &Measurement{
				Type:      AWSNitroEnclaveV1,
				Registers: []string{"reg1", "reg2"},
			},
			m2: &Measurement{
				Type:      "other-type",
				Registers: []string{"reg1", "reg2"},
			},
			wantErr: ErrFormatMismatch,
		},
		{
			name: "different register lengths",
			m1: &Measurement{
				Type:      AWSNitroEnclaveV1,
				Registers: []string{"reg1", "reg2"},
			},
			m2: &Measurement{
				Type:      AWSNitroEnclaveV1,
				Registers: []string{"reg1"},
			},
			wantErr: ErrMeasurementMismatch,
		},
		{
			name: "different register values",
			m1: &Measurement{
				Type:      AWSNitroEnclaveV1,
				Registers: []string{"reg1", "reg2"},
			},
			m2: &Measurement{
				Type:      AWSNitroEnclaveV1,
				Registers: []string{"reg1", "reg3"},
			},
			wantErr: ErrMeasurementMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.m1.Equals(tt.m2), tt.wantErr)
		})
	}
}
