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
			name:    "same measurements",
			wantErr: nil,
			m1: &Measurement{
				Type:      AWSNitroEnclaveV1,
				Registers: []string{"reg1", "reg2"},
			},
			m2: &Measurement{
				Type:      AWSNitroEnclaveV1,
				Registers: []string{"reg1", "reg2"},
			},
		}, {
			name:    "different types",
			wantErr: ErrFormatMismatch,
			m1: &Measurement{
				Type:      AWSNitroEnclaveV1,
				Registers: []string{"reg1", "reg2"},
			},
			m2: &Measurement{
				Type:      "other-type",
				Registers: []string{"reg1", "reg2"},
			},
		}, {
			name:    "different register lengths",
			wantErr: ErrMeasurementMismatch,
			m1: &Measurement{
				Type:      AWSNitroEnclaveV1,
				Registers: []string{"reg1", "reg2"},
			},
			m2: &Measurement{
				Type:      AWSNitroEnclaveV1,
				Registers: []string{"reg1"},
			},
		}, {
			name:    "different register values",
			wantErr: ErrMeasurementMismatch,
			m1: &Measurement{
				Type:      AWSNitroEnclaveV1,
				Registers: []string{"reg1", "reg2"},
			},
			m2: &Measurement{
				Type:      AWSNitroEnclaveV1,
				Registers: []string{"reg1", "reg3"},
			},
		}, {
			name:    "multi-platform measurement first",
			wantErr: nil,
			m1: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1", "rtmr2"},
			},
			m2: &Measurement{
				Type:      TdxGuestV1,
				Registers: []string{"mrtd", "rtmr0", "rtmr1", "rtmr2"},
			},
		}, {
			name:    "multi-platform measurement second (gets flipped)",
			wantErr: nil,
			m1: &Measurement{
				Type:      TdxGuestV1,
				Registers: []string{"mrtd", "rtmr0", "rtmr1", "rtmr2"},
			},
			m2: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1", "rtmr2"},
			},
		}, {
			name:    "multi-platform RTMR1 mismatch",
			wantErr: ErrRtmr1Mismatch,
			m1: &Measurement{
				Type:      TdxGuestV1,
				Registers: []string{"mrtd", "rtmr0", "rtmr1", "rtmr2"},
			},
			m2: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1_other", "rtmr2"},
			},
		}, {
			name:    "multi-platform RTMR2 mismatch",
			wantErr: ErrRtmr2Mismatch,
			m1: &Measurement{
				Type:      TdxGuestV1,
				Registers: []string{"mrtd", "rtmr0", "rtmr1", "rtmr2"},
			},
			m2: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1", "rtmr2_other"},
			},
		}, {
			name:    "multi-platform few registers",
			wantErr: ErrFewRegisters,
			m1: &Measurement{
				Type:      TdxGuestV1,
				Registers: []string{"mrtd", "rtmr0", "rtmr1", "rtmr2"},
			},
			m2: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1"},
			},
		}, {
			name:    "multi-platform enclave side few registers",
			wantErr: ErrFewRegisters,
			m1: &Measurement{
				Type:      TdxGuestV1,
				Registers: []string{"mrtd", "rtmr0", "rtmr1"},
			},
			m2: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1", "rtmr2"},
			},
		}, {
			name:    "multi-platform SEV-SNP ok",
			wantErr: nil,
			m1: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1", "rtmr2"},
			},
			m2: &Measurement{
				Type:      SevGuestV1,
				Registers: []string{"sevsnp"},
			},
		}, {
			name:    "multi-platform SEV-SNP mismatch",
			wantErr: ErrMeasurementMismatch,
			m1: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1", "rtmr2"},
			},
			m2: &Measurement{
				Type:      SevGuestV1,
				Registers: []string{"sevsnp_other"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.m1.Equals(tt.m2), tt.wantErr)
		})
	}
}
