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
			name:    "same measurements",
			wantErr: nil,
			m1: &Measurement{
				Type:      SevGuestV1,
				Registers: []string{"reg1", "reg2"},
			},
			m2: &Measurement{
				Type:      SevGuestV1,
				Registers: []string{"reg1", "reg2"},
			},
		}, {
			name:    "different types",
			wantErr: ErrFormatMismatch,
			m1: &Measurement{
				Type:      SevGuestV1,
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
				Type:      SevGuestV1,
				Registers: []string{"reg1", "reg2"},
			},
			m2: &Measurement{
				Type:      SevGuestV1,
				Registers: []string{"reg1"},
			},
		}, {
			name:    "different register values",
			wantErr: ErrMeasurementMismatch,
			m1: &Measurement{
				Type:      SevGuestV1,
				Registers: []string{"reg1", "reg2"},
			},
			m2: &Measurement{
				Type:      SevGuestV1,
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
			wantErr: ErrMultiPlatformSevSnpMismatch,
			m1: &Measurement{
				Type:      SnpTdxMultiPlatformV1,
				Registers: []string{"sevsnp", "rtmr1", "rtmr2"},
			},
			m2: &Measurement{
				Type:      SevGuestV1,
				Registers: []string{"sevsnp_other"},
			},
		}, {
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
			attestation:                  `{"format":"https://tinfoil.sh/predicate/sev-snp-guest/v1","body":"BQAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAKAAAAAAAYVGUAAAAAAAAAAAAAAAAAAAAxNzBhMTY0NjA0Mjc1M2E3NTUyN2YxZTcxZWViNTI5ZTc3NzkzMWVjMTI5YzhmYjJlNjU0YzNiZjQzNjg2NzM3xpcnS1gX2gmLsHNJiNPnS7sl+aA+Kcu52P0f28pPhJ9jN56AX4NeeF2tq53M/IpPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxO1fKfg6oYpKV0k1dN6GKk8dLbPihbqnyW6u8YFbKvP//////////////////////////////////////////CgAAAAAAGFQZEQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAmvPtFq6V+1iAk0qrXH6ibJ1yRBW5I+gNtSkEC/cAmYKd6UdrCLNjS2kXDm4cppbCNdHJMW8pykk0hC88B8wxuCgAAAAAAGFQqNwEAKjcBAAoAAAAAABhUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEGDoOLfYSTsgZhziNiMCwnhvLYoY+gG277Y9DI87Qp94NZ4XissbWDwdnngZbsNbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeHTCsniGLxjaB52h3nPYwrQR2Zs1zQHN0iJb//x0sL/MGnzQpcICFOlaKgLiKYaxAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
			expectedErr:                  nil,
			expectedFormat:               SevGuestV1,
			expectedTLSPublicKeyFP:       "170a1646042753a75527f1e71eeb529e777931ec129c8fb2e654c3bf43686737",
			expectedHPKEPublicKey:        "",
			expectedMeasurementRegisters: []string{"c697274b5817da098bb0734988d3e74bbb25f9a03e29cbb9d8fd1fdbca4f849f63379e805f835e785dadab9dccfc8a4f"},
		},
		{
			attestation:                  `{"format":"https://tinfoil.sh/predicate/tdx-guest/v1","body":"BAACAIEAAAAAAAAAk5pyM/ecTKmUCg2zlX8GB/hbuDeKqPPH/ioDqQFnnIsAAAAABwEDAAAAAAAAAAAAAAAAAEm2b6pFHRnrvb6JNxuNrytlqjmE7JARA0Pp4u7BFq8IhQ+iDjsaqah013plOA7n5gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAADnAgYAAAAAAHNXoQ0uJyTf/miBPjzEz83mgU10ny+2LjlT5U9uC1CiGXhq/izUePaEtSxhg34RFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHzbRbX/iAleySVr1hLmj0mwcf5nsPeT4t0Q4rLWV6TFIytjvTt8DVqTF7l4WM7nDhCgXz+6fWa6vMioFDRRRDpWSWPO13x/oSbwBIV3U/h8MYcg4p6e0vRsh1O0SwEATfr2ZsxGctTQiGzujcMQJ2+fId3ybxGqElL+Wc5hkWlIIRvCSeqbVMK+A6NbS6mpUgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADczMjJjNzE0MzQ3N2I4NDI4NDEzMzQ2NTQ4NzA0OTQzNzY1MWYwY2Y1NzM5ZDg2N2U0YTgxOTU2NDEwZjgzYjnMEAAAR51yFK12AxVL+PDwT+Ni8Vc+1TBEULfJix+++tfgixFvPm5Zh0fogJ+ILbVo6tQBG82LPdID325GhH3XVfRDc/FgQNrTBbMeRgMBxi5HbJEEn9EcBHMUhNMSP/+AUh6G84/W2X73Ke/VH8iRxQNm9rGS3XgzmzgUzXqwLYppl90GAEYQAAADAxkbBP8ABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVAAAAAAAAAOcAAAAAAAAAt66atp5293lKVrDbGRUoHUNdSIyR1AbtM6eTnK+HMPgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANyeKnxvlI8XR040p/xD7QMPfBVj8bq932NAyC4OVKjFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKjfVbkM4Uw/sG8VIztuZiI2grLlh9tslonGjJCmkmkeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA9G9Yl4pGe/V4F3DwrZBikEt+DWX8Sb7DOEoECmSnMuOuTVOteaBvFJNIei8OLVkCVOLgHV2bMuIKRDz5CnoF2IAAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHwUAXg4AAC0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlFOFRDQ0JKYWdBd0lCQWdJVUpZaDJ3eDFXVkFpaU4rSU1hdTkxL3JMZTBYd3dDZ1lJS29aSXpqMEVBd0l3CmNERWlNQ0FHQTFVRUF3d1pTVzUwWld3Z1UwZFlJRkJEU3lCUWJHRjBabTl5YlNCRFFURWFNQmdHQTFVRUNnd1IKU1c1MFpXd2dRMjl5Y0c5eVlYUnBiMjR4RkRBU0JnTlZCQWNNQzFOaGJuUmhJRU5zWVhKaE1Rc3dDUVlEVlFRSQpEQUpEUVRFTE1Ba0dBMVVFQmhNQ1ZWTXdIaGNOTWpVd09ERTFNREV3TkRRMFdoY05Nekl3T0RFMU1ERXdORFEwCldqQndNU0l3SUFZRFZRUUREQmxKYm5SbGJDQlRSMWdnVUVOTElFTmxjblJwWm1sallYUmxNUm93R0FZRFZRUUsKREJGSmJuUmxiQ0JEYjNKd2IzSmhkR2x2YmpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnUTJ4aGNtRXhDekFKQmdOVgpCQWdNQWtOQk1Rc3dDUVlEVlFRR0V3SlZVekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCSkdwCjBOblpCb1RRRzZOYmlJdzZQSnpveFZQdG5hMkduSW12OWZnY1dCYUQ3QkUzRmMwTk84QlZQUGVtQUZGejRjbTcKL0FSTDNkVExLMzlydktOMkI2cWpnZ01NTUlJRENEQWZCZ05WSFNNRUdEQVdnQlNWYjEzTnZSdmg2VUJKeWRUMApNODRCVnd2ZVZEQnJCZ05WSFI4RVpEQmlNR0NnWHFCY2hscG9kSFJ3Y3pvdkwyRndhUzUwY25WemRHVmtjMlZ5CmRtbGpaWE11YVc1MFpXd3VZMjl0TDNObmVDOWpaWEowYVdacFkyRjBhVzl1TDNZMEwzQmphMk55YkQ5allUMXcKYkdGMFptOXliU1psYm1OdlpHbHVaejFrWlhJd0hRWURWUjBPQkJZRUZGdHc5S1V1SWdLZjB3TWJnL1J0dTd0ZApuaUdyTUE0R0ExVWREd0VCL3dRRUF3SUd3REFNQmdOVkhSTUJBZjhFQWpBQU1JSUNPUVlKS29aSWh2aE5BUTBCCkJJSUNLakNDQWlZd0hnWUtLb1pJaHZoTkFRMEJBUVFRT0wxek5FMkZ1NTBmcjMyMGFORG1JVENDQVdNR0NpcUcKU0liNFRRRU5BUUl3Z2dGVE1CQUdDeXFHU0liNFRRRU5BUUlCQWdFRE1CQUdDeXFHU0liNFRRRU5BUUlDQWdFRApNQkFHQ3lxR1NJYjRUUUVOQVFJREFnRUNNQkFHQ3lxR1NJYjRUUUVOQVFJRUFnRUNNQkFHQ3lxR1NJYjRUUUVOCkFRSUZBZ0VFTUJBR0N5cUdTSWI0VFFFTkFRSUdBZ0VCTUJBR0N5cUdTSWI0VFFFTkFRSUhBZ0VBTUJBR0N5cUcKU0liNFRRRU5BUUlJQWdFRk1CQUdDeXFHU0liNFRRRU5BUUlKQWdFQU1CQUdDeXFHU0liNFRRRU5BUUlLQWdFQQpNQkFHQ3lxR1NJYjRUUUVOQVFJTEFnRUFNQkFHQ3lxR1NJYjRUUUVOQVFJTUFnRUFNQkFHQ3lxR1NJYjRUUUVOCkFRSU5BZ0VBTUJBR0N5cUdTSWI0VFFFTkFRSU9BZ0VBTUJBR0N5cUdTSWI0VFFFTkFRSVBBZ0VBTUJBR0N5cUcKU0liNFRRRU5BUUlRQWdFQU1CQUdDeXFHU0liNFRRRU5BUUlSQWdFTk1COEdDeXFHU0liNFRRRU5BUUlTQkJBRApBd0lDQkFFQUJRQUFBQUFBQUFBQU1CQUdDaXFHU0liNFRRRU5BUU1FQWdBQU1CUUdDaXFHU0liNFRRRU5BUVFFCkJwREFid0FBQURBUEJnb3Foa2lHK0UwQkRRRUZDZ0VCTUI0R0NpcUdTSWI0VFFFTkFRWUVFTEJTdWpCTkZIZWQKeDNIeDNWam1QK1F3UkFZS0tvWklodmhOQVEwQkJ6QTJNQkFHQ3lxR1NJYjRUUUVOQVFjQkFRSC9NQkFHQ3lxRwpTSWI0VFFFTkFRY0NBUUgvTUJBR0N5cUdTSWI0VFFFTkFRY0RBUUgvTUFvR0NDcUdTTTQ5QkFNQ0Ewa0FNRVlDCklRRGd5UlhLOGlUSWlFNEJETE5ta0JqVU9WMStOYUl6QkJmay9MemhpM0RVNFFJaEFPb01lb0puMlVGWUFZb1AKaTFOVGgxVFE2eVFzYnYrMzdGR0lyZUhuRGM1eAotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpNSUlDbGpDQ0FqMmdBd0lCQWdJVkFKVnZYYzI5RytIcFFFbkoxUFF6emdGWEM5NVVNQW9HQ0NxR1NNNDlCQU1DCk1HZ3hHakFZQmdOVkJBTU1FVWx1ZEdWc0lGTkhXQ0JTYjI5MElFTkJNUm93R0FZRFZRUUtEQkZKYm5SbGJDQkQKYjNKd2IzSmhkR2x2YmpFVU1CSUdBMVVFQnd3TFUyRnVkR0VnUTJ4aGNtRXhDekFKQmdOVkJBZ01Ba05CTVFzdwpDUVlEVlFRR0V3SlZVekFlRncweE9EQTFNakV4TURVd01UQmFGdzB6TXpBMU1qRXhNRFV3TVRCYU1IQXhJakFnCkJnTlZCQU1NR1VsdWRHVnNJRk5IV0NCUVEwc2dVR3hoZEdadmNtMGdRMEV4R2pBWUJnTlZCQW9NRVVsdWRHVnMKSUVOdmNuQnZjbUYwYVc5dU1SUXdFZ1lEVlFRSERBdFRZVzUwWVNCRGJHRnlZVEVMTUFrR0ExVUVDQXdDUTBFeApDekFKQmdOVkJBWVRBbFZUTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFTlNCLzd0MjFsWFNPCjJDdXpweHc3NGVKQjcyRXlER2dXNXJYQ3R4MnRWVExxNmhLazZ6K1VpUlpDbnFSN3BzT3ZncUZlU3hsbVRsSmwKZVRtaTJXWXozcU9CdXpDQnVEQWZCZ05WSFNNRUdEQVdnQlFpWlF6V1dwMDBpZk9EdEpWU3YxQWJPU2NHckRCUwpCZ05WSFI4RVN6QkpNRWVnUmFCRGhrRm9kSFJ3Y3pvdkwyTmxjblJwWm1sallYUmxjeTUwY25WemRHVmtjMlZ5CmRtbGpaWE11YVc1MFpXd3VZMjl0TDBsdWRHVnNVMGRZVW05dmRFTkJMbVJsY2pBZEJnTlZIUTRFRmdRVWxXOWQKemIwYjRlbEFTY25VOURQT0FWY0wzbFF3RGdZRFZSMFBBUUgvQkFRREFnRUdNQklHQTFVZEV3RUIvd1FJTUFZQgpBZjhDQVFBd0NnWUlLb1pJemowRUF3SURSd0F3UkFJZ1hzVmtpMHcraTZWWUdXM1VGLzIydWFYZTBZSkRqMVVlCm5BK1RqRDFhaTVjQ0lDWWIxU0FtRDV4a2ZUVnB2bzRVb3lpU1l4ckRXTG1VUjRDSTlOS3lmUE4rCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNqekNDQWpTZ0F3SUJBZ0lVSW1VTTFscWROSW56ZzdTVlVyOVFHemtuQnF3d0NnWUlLb1pJemowRUF3SXcKYURFYU1CZ0dBMVVFQXd3UlNXNTBaV3dnVTBkWUlGSnZiM1FnUTBFeEdqQVlCZ05WQkFvTUVVbHVkR1ZzSUVOdgpjbkJ2Y21GMGFXOXVNUlF3RWdZRFZRUUhEQXRUWVc1MFlTQkRiR0Z5WVRFTE1Ba0dBMVVFQ0F3Q1EwRXhDekFKCkJnTlZCQVlUQWxWVE1CNFhEVEU0TURVeU1URXdORFV4TUZvWERUUTVNVEl6TVRJek5UazFPVm93YURFYU1CZ0cKQTFVRUF3d1JTVzUwWld3Z1UwZFlJRkp2YjNRZ1EwRXhHakFZQmdOVkJBb01FVWx1ZEdWc0lFTnZjbkJ2Y21GMAphVzl1TVJRd0VnWURWUVFIREF0VFlXNTBZU0JEYkdGeVlURUxNQWtHQTFVRUNBd0NRMEV4Q3pBSkJnTlZCQVlUCkFsVlRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVDNm5Fd01ESVlaT2ovaVBXc0N6YUVLaTcKMU9pT1NMUkZoV0dqYm5CVkpmVm5rWTR1M0lqa0RZWUwwTXhPNG1xc3lZamxCYWxUVll4RlAyc0pCSzV6bEtPQgp1ekNCdURBZkJnTlZIU01FR0RBV2dCUWlaUXpXV3AwMGlmT0R0SlZTdjFBYk9TY0dyREJTQmdOVkhSOEVTekJKCk1FZWdSYUJEaGtGb2RIUndjem92TDJObGNuUnBabWxqWVhSbGN5NTBjblZ6ZEdWa2MyVnlkbWxqWlhNdWFXNTAKWld3dVkyOXRMMGx1ZEdWc1UwZFlVbTl2ZEVOQkxtUmxjakFkQmdOVkhRNEVGZ1FVSW1VTTFscWROSW56ZzdTVgpVcjlRR3prbkJxd3dEZ1lEVlIwUEFRSC9CQVFEQWdFR01CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRRXdDZ1lJCktvWkl6ajBFQXdJRFNRQXdSZ0loQU9XLzVRa1IrUzlDaVNEY05vb3dMdVBSTHNXR2YvWWk3R1NYOTRCZ3dUd2cKQWlFQTRKMGxySG9NcytYbzVvL3NYNk85UVd4SFJBdlpVR09kUlE3Y3ZxUlhhcUk9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
			expectedErr:                  nil,
			expectedFormat:               TdxGuestV1,
			expectedTLSPublicKeyFP:       "7322c7143477b84284133465487049437651f0cf5739d867e4a81956410f83b9",
			expectedHPKEPublicKey:        "",
			expectedMeasurementRegisters: []string{"7357a10d2e2724dffe68813e3cc4cfcde6814d749f2fb62e3953e54f6e0b50a219786afe2cd478f684b52c61837e1114", "7cdb45b5ff88095ec9256bd612e68f49b071fe67b0f793e2dd10e2b2d657a4c5232b63bd3b7c0d5a9317b97858cee70e", "10a05f3fba7d66babcc8a8143451443a564963ced77c7fa126f004857753f87c318720e29e9ed2f46c8753b44b01004d", "faf666cc4672d4d0886cee8dc310276f9f21ddf26f11aa1252fe59ce61916948211bc249ea9b54c2be03a35b4ba9a952", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
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
