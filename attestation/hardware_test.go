package attestation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttestationVerifyHardware(t *testing.T) {
	measurements := []*HardwareMeasurement{
		{
			ID:    "alpha@0",
			MRTD:  "abcdef",
			RTMR0: "012345",
		},
	}

	match, err := VerifyHardware(measurements, &Measurement{
		Type: TdxGuestV1,
		Registers: []string{
			"abcdef",
			"012345",
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "alpha@0", match.ID)

	match, err = VerifyHardware(measurements, &Measurement{
		Type: TdxGuestV1,
		Registers: []string{
			"aaaaaa",
			"bbbbbb",
		},
	})
	assert.Error(t, err)
	assert.Empty(t, match)
}
