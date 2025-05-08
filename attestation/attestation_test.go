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
			name:    "same measurements Nitro",
			m1:      NewNitroMeasurement("reg1", "reg2", "reg3"),
			m2:      NewNitroMeasurement("reg1", "reg2", "reg3"),
			wantErr: nil,
		},
		{
			name:    "same measurements SEV",
			m1:      NewSevMeasurement("reg1"),
			m2:      NewSevMeasurement("reg1"),
			wantErr: nil,
		},
		{
			name:    "different types",
			m1:      NewNitroMeasurement("reg1", "reg2", "reg3"),
			m2:      NewSevMeasurement("reg1"),
			wantErr: ErrFormatMismatch,
		},
		{
			name:    "different register values Nitro",
			m1:      NewNitroMeasurement("reg1", "reg2", "reg3"),
			m2:      NewNitroMeasurement("reg1", "reg3", "reg4"),
			wantErr: ErrMeasurementMismatch,
		},
		{
			name:    "different register values SEV",
			m1:      NewSevMeasurement("reg1"),
			m2:      NewSevMeasurement("reg2"),
			wantErr: ErrMeasurementMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.m1.Compare(tt.m2), tt.wantErr)
		})
	}
}
