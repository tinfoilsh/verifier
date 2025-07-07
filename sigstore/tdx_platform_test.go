package sigstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFetchTDXPlatformMeasurements(t *testing.T) {
	client, err := NewClient()
	assert.NoError(t, err)
	measurements, err := client.FetchTDXPlatformMeasurements(
		"tinfoilsh/tdx-hardware",
		"5c4e395668bbcc1b576dbfe6c9b2aae293f6e8da77fa36bf1d4293f52d705674",
	)
	assert.NoError(t, err)

	assert.Equal(t, measurements["hw1"].MRTD, "7ce4cec5729d95652108c1dfe381a3ccb6a6a9061920f0479a3e4c7c806cf51d2438958def083084880f2bf4dd2e14eb")
	assert.Equal(t, measurements["hw1"].RTMR0, "715127652af6ebda5c44687778d813472c558e4f15efad0e3bcfe8fba999c23154eff827840fef15bbb2027fd3c84ab1")
	assert.Empty(t, measurements["hw1"].RTMR1)
	assert.Empty(t, measurements["hw1"].RTMR2)
}
