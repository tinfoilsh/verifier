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
		{
			ID:    "beta@1",
			MRTD:  "fedcba",
			RTMR0: "543210",
		},
	}

	t.Run("TdxGuestV2 successful match", func(t *testing.T) {
		match, err := VerifyHardware(measurements, &Measurement{
			Type: TdxGuestV2,
			Registers: []string{
				"fedcba",
				"543210",
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, "beta@1", match.ID)
		assert.Equal(t, "fedcba", match.MRTD)
		assert.Equal(t, "543210", match.RTMR0)
	})

	t.Run("TdxGuestV2 no match found", func(t *testing.T) {
		match, err := VerifyHardware(measurements, &Measurement{
			Type: TdxGuestV2,
			Registers: []string{
				"cccccc",
				"dddddd",
			},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no matching hardware platform found")
		assert.Nil(t, match)
	})

	t.Run("nil enclave measurement", func(t *testing.T) {
		match, err := VerifyHardware(measurements, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "enclave measurement is nil")
		assert.Nil(t, match)
	})

	t.Run("unsupported enclave platform", func(t *testing.T) {
		match, err := VerifyHardware(measurements, &Measurement{
			Type: "unsupported-platform",
			Registers: []string{
				"abcdef",
				"012345",
			},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported enclave platform: unsupported-platform")
		assert.Nil(t, match)
	})

	t.Run("empty registers", func(t *testing.T) {
		match, err := VerifyHardware(measurements, &Measurement{
			Type:      TdxGuestV2,
			Registers: []string{},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "enclave provided fewer registers than expected: 0")
		assert.Nil(t, match)
	})

}
