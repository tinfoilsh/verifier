package sigstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinfoilsh/verifier/attestation"
	"github.com/tinfoilsh/verifier/github"
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
	assert.Equal(t, "7357a10d2e2724dffe68813e3cc4cfcde6814d749f2fb62e3953e54f6e0b50a219786afe2cd478f684b52c61837e1114", hw1measurement.MRTD)
	assert.Equal(t, hw1measurement.RTMR0, "5c70e5e513f82d930e4740228a51a96fb981dd8e63a583aae5d71c84caaa06c1241c4eaf46faab066d0120e44bf5a1e1")
}

func TestVerifyAttestation(t *testing.T) {
	client, err := NewClient()
	assert.NoError(t, err)

	const repo = "tinfoilsh/confidential-deepseek-r1-0528"
	const hexDigest = "7e76d5a6d81f19ecdc1f3c18c8f0cf5b89d22ea107a05a1ae23ce46e79270f26"
	bundle, err := github.FetchAttestationBundle(repo, hexDigest)
	assert.NoError(t, err)

	measurement, err := client.VerifyAttestation(bundle, hexDigest, repo)
	assert.NoError(t, err)
	assert.Equal(t, measurement.Type, attestation.SnpTdxMultiPlatformV1)
	assert.Equal(t, measurement.Registers, []string{
		"442df00d945bdd2849e6df4eb28c757e9e94428787268b452eacb3f86bbc38528d6712e2c41b6953f1a96d2493d5f9b6", // SEV-SNP
		"10a05f3fba7d66babcc8a8143451443a564963ced77c7fa126f004857753f87c318720e29e9ed2f46c8753b44b01004d", // RTRM1
		"fc744ecc4550ec0ea6c25deaa777bd2ed6e5feda35ac1e88a2c2b6e62584a8ad47a93526638de3b97fe45cd67cb5339f", // RTRM2
	})

	// Check TDX equality
	tdxMeasurement := &attestation.Measurement{
		Type: attestation.TdxGuestV1,
		Registers: []string{
			"mrtd",
			"rtrm0",
			"10a05f3fba7d66babcc8a8143451443a564963ced77c7fa126f004857753f87c318720e29e9ed2f46c8753b44b01004d", // RTMR1
			"fc744ecc4550ec0ea6c25deaa777bd2ed6e5feda35ac1e88a2c2b6e62584a8ad47a93526638de3b97fe45cd67cb5339f", // RTMR2
		},
	}
	assert.NoError(t, measurement.Equals(tdxMeasurement))

	// Check SEV-SNP equality
	sevSNPMeasurement := &attestation.Measurement{
		Type: attestation.SevGuestV1,
		Registers: []string{
			"442df00d945bdd2849e6df4eb28c757e9e94428787268b452eacb3f86bbc38528d6712e2c41b6953f1a96d2493d5f9b6", // SEV-SNP
		},
	}
	assert.NoError(t, measurement.Equals(sevSNPMeasurement))
}
