package attestation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMeasurementEquals(t *testing.T) {
	tests := []struct {
		name    string
		m1      *Measurement
		m2      *Measurement
		wantErr error
	}{

		{
			name:    "multi-platform to multi-platform equal",
			wantErr: nil,
			m1: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1", "rtmr2"},
			},
			m2: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1", "rtmr2"},
			},
		}, {
			name:    "multi-platform to multi-platform mismatch",
			wantErr: ErrMultiPlatformMismatch,
			m1: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1", "rtmr2"},
			},
			m2: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp_other", "rtmr1", "rtmr2"},
			},
		}, {
			name:    "multi-platform SEV-SNP v2 match",
			wantErr: nil,
			m1: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1", "rtmr2"},
			},
			m2: &Measurement{
				Type:      SevGuestV2,
				Registers: []string{"sevsnp"},
			},
		}, {
			name:    "multi-platform TDX v2 match",
			wantErr: nil,
			m1: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1", "rtmr2"},
			},
			m2: &Measurement{
				Type:      TdxGuestV2,
				Registers: []string{"mrtd", "rtmr0", "rtmr1", "rtmr2", RTMR3_ZERO},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.m1.Equals(tt.m2), tt.wantErr)
		})
	}
}

func TestGuestVerify(t *testing.T) {
	tcs := []struct {
		attestation                  string
		expectedErr                  error
		expectedFormat               PredicateType
		expectedTLSPublicKeyFP       string
		expectedHPKEPublicKey        string
		expectedMeasurementRegisters []string
	}{
		{
			attestation:                  `{"format":"https://tinfoil.sh/predicate/sev-snp-guest/v2","body":"H4sIAAAAAAAA/2JmgAEEixBgZGBg4AKzxEPU0eQETrU6V/UVB3t6X/nzPHnDqkuB7Ge7tj5ZEHio29Wfkc1uX9Sclq9brfxurj5f8/1vsLnEKWGd+VvbrZlW1uopNP7g1X277qF1y53Evj/F31o35j7JULPg0r0S+zF28d3utXtmKJ26X/2ndOpEHVfxXfmrpYMOEO1oGgGNBec2/VR6lX2Gl0OiQHRZX6rfLIn+iuYbKf+jFB4bqZ34TwDAwlFSkBGr+VIfV+XIhzFXsbbMitzRGPOTM8J+9sr3+qxGEkfMP1svbH7yRHSD5eb6JlZVrovx3R0LFq+9+eVA44HyWR5vlUTM+1xg5muYMzKAMIxPxyCiCHQ6e7XWK8xY82mR/JozTx04Vy5l8FSb5PHojvm2wD2bL32f4PhFweCczqKfEgb9gr/XG+Iy57HDxR1FBzhUzT5FZUW/TOHzX/fB7uei0kcHzO5v62TjbzG4Zxh1YsrdgwmpTrsN8vatoq8vRwEuAAgAAP//tiY3daAEAAA="}`,
			expectedErr:                  nil,
			expectedFormat:               SevGuestV2,
			expectedTLSPublicKeyFP:       "10ca85437a8e7353494bd4fce763b0aad25107cd8ab5e4a051c28b454f01063e",
			expectedHPKEPublicKey:        "be5a9c84f5b53a4ed9abcf7cf7fd533718ca132c9fb5873b02a97d2e2081f80d",
			expectedMeasurementRegisters: []string{"2dedaee13b84dc618efc73f685b16de46826380a2dd45df15da3dd8badbc9822cadf7bfc7595912c4517ba6fab1b52c0"},
		},
		{
			attestation:                  `{"format":"https://tinfoil.sh/predicate/tdx-guest/v2","body":"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"}`,
			expectedErr:                  nil,
			expectedFormat:               TdxGuestV2,
			expectedTLSPublicKeyFP:       "a23b0e7747d73bba1c4a9dc4610584e37b6e9fba4d9133c2804d95572c13c0fa",
			expectedHPKEPublicKey:        "d34fcf36c21e383632ed361527c68db541e84f89ec9268addccb892c60ea2824",
			expectedMeasurementRegisters: []string{"7357a10d2e2724dffe68813e3cc4cfcde6814d749f2fb62e3953e54f6e0b50a219786afe2cd478f684b52c61837e1114", "18945fe4f04d952afb91035b74c2527e38458fd972bee01b7ba02004dc0f2fec2ec90825702956cb76f52f5c1d9f5021", "896d8b9138548e63779a121b8c2b1a087ddaa39901e1fd096319ff0005b9699fe04dd13adb33063a1d65dd4bcdc2f5b1", "96a980ecd429079996c94413bc4c4c2bfcf652d626b6daf2a520206ead5065dd53001c2b583a5fbe41921581e25f669c", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
		},
	}
	for _, tc := range tcs {
		t.Run("", func(t *testing.T) {
			verification, err := VerifyAttestationJSON([]byte(tc.attestation))
			require.NoError(t, err)
			assert.Equal(t, tc.expectedFormat, verification.Measurement.Type)
			assert.Equal(t, tc.expectedErr, err)
			assert.Equal(t, tc.expectedTLSPublicKeyFP, verification.TLSPublicKeyFP)
			assert.Equal(t, tc.expectedHPKEPublicKey, verification.HPKEPublicKey)
			assert.Equal(t, tc.expectedMeasurementRegisters, verification.Measurement.Registers)
		})
	}
}

func TestFetchBundle(t *testing.T) {
	bundle, err := FetchBundle()
	require.NoError(t, err)
	require.NotNil(t, bundle)

	assert.NotEmpty(t, bundle.Domain)
	assert.NotEmpty(t, bundle.Digest)
	assert.NotNil(t, bundle.EnclaveAttestationReport)
	assert.NotEmpty(t, bundle.EnclaveAttestationReport.Format)
	assert.NotEmpty(t, bundle.EnclaveAttestationReport.Body)
	assert.NotEmpty(t, bundle.VCEK)
	assert.NotEmpty(t, bundle.SigstoreBundle)
}

func TestAttestationFingerprint(t *testing.T) {
	routerMpMeasurement := &Measurement{
		Type: SnpTdxMultiPlatformV1,
		Registers: []string{
			"33162608e171154bae88886365341dad7eb5821ba87785041f7f2f6281511a65b01069894cfebad5370939e05a0a1ca1",
			"896d8b9138548e63779a121b8c2b1a087ddaa39901e1fd096319ff0005b9699fe04dd13adb33063a1d65dd4bcdc2f5b1",
			"fbe40d6adb70ef8047dbfbd9be05fcf39d9dd32d5b88c70dd5c06024d3a8d79a5d2e9e9723d3b3cb206bfd887eddcdec",
		},
	}

	tcs := []struct {
		sourceMeasurement   *Measurement
		enclaveMeasurement  *Measurement
		hwMeasurement       *HardwareMeasurement
		expectedFingerprint string
	}{
		{
			sourceMeasurement: routerMpMeasurement,
			enclaveMeasurement: &Measurement{
				Type: TdxGuestV2,
				Registers: []string{
					"7357a10d2e2724dffe68813e3cc4cfcde6814d749f2fb62e3953e54f6e0b50a219786afe2cd478f684b52c61837e1114",
					"304a1788d349864a75d7e76d54c8d0223207f990e84ad087d28787fff0a7b7cff14c5cb9a96f91ca02e8b32884d9fa81",
					"896d8b9138548e63779a121b8c2b1a087ddaa39901e1fd096319ff0005b9699fe04dd13adb33063a1d65dd4bcdc2f5b1",
					"fbe40d6adb70ef8047dbfbd9be05fcf39d9dd32d5b88c70dd5c06024d3a8d79a5d2e9e9723d3b3cb206bfd887eddcdec",
					"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				},
			},
			hwMeasurement: &HardwareMeasurement{
				MRTD:  "7357a10d2e2724dffe68813e3cc4cfcde6814d749f2fb62e3953e54f6e0b50a219786afe2cd478f684b52c61837e1114",
				RTMR0: "304a1788d349864a75d7e76d54c8d0223207f990e84ad087d28787fff0a7b7cff14c5cb9a96f91ca02e8b32884d9fa81",
			},
			expectedFingerprint: "874cf5dbe488abcfc2a6dec361483c0e7145f59ada762d6ae6f8f8da3a264323",
		}, {
			sourceMeasurement: routerMpMeasurement,
			enclaveMeasurement: &Measurement{
				Type:      SevGuestV2,
				Registers: []string{"33162608e171154bae88886365341dad7eb5821ba87785041f7f2f6281511a65b01069894cfebad5370939e05a0a1ca1"},
			},
			hwMeasurement:       nil,
			expectedFingerprint: "08ea4d8c2e8da077c682529d3cd1d1500d84e100df6b81781e38733f0589cfa1",
		},
	}

	for _, tc := range tcs {
		t.Run("", func(t *testing.T) {
			enclaveFP, err := Fingerprint(tc.enclaveMeasurement, tc.hwMeasurement, tc.enclaveMeasurement.Type)
			require.NoError(t, err)

			sourceFP, err := Fingerprint(tc.sourceMeasurement, tc.hwMeasurement, tc.enclaveMeasurement.Type)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedFingerprint, sourceFP)
			assert.Equal(t, tc.expectedFingerprint, enclaveFP)
		})
	}
}
