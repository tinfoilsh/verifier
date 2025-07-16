package sigstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinfoilsh/verifier/attestation"
)

func TestFetchHardwarePlatformMeasurements(t *testing.T) {
	client, err := NewClient()
	assert.NoError(t, err)

	const digest = "fe03832f4045909235b2c4f62a2dcfce4212383e48d111f65eb3971af264a9bc"

	measurements, err := client.FetchHardwareMeasurements("tinfoilsh/hardware-measurements", digest)
	assert.NoError(t, err)

	var hw1measurement *attestation.HardwareMeasurement
	for _, measurement := range measurements {
		if measurement.ID == "hw1@"+digest {
			hw1measurement = measurement
			break
		}
	}

	assert.NotNil(t, hw1measurement)
	assert.Equal(t, hw1measurement.MRTD, "7357a10d2e2724dffe68813e3cc4cfcde6814d749f2fb62e3953e54f6e0b50a219786afe2cd478f684b52c61837e1114")
	assert.Equal(t, hw1measurement.RTMR0, "5c70e5e513f82d930e4740228a51a96fb981dd8e63a583aae5d71c84caaa06c1241c4eaf46faab066d0120e44bf5a1e1")
}
