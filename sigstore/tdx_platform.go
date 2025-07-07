package sigstore

import (
	"github.com/tinfoilsh/verifier/github"
)

// TDXMeasurement represents the measurement values from a TDX enclave
type TDXMeasurement struct {
	MRTD  string
	RTMR0 string
	RTMR1 string
	RTMR2 string
}

// FetchTDXPlatformMeasurements fetches the MRTD and RTMR0 from a given hardware repo
func (c *Client) FetchTDXPlatformMeasurements(repo, digest string) (map[string]TDXMeasurement, error) {
	sigstoreBundle, err := github.FetchAttestationBundle(repo, digest)
	if err != nil {
		return nil, err
	}

	bundle, err := c.verifyBundle(sigstoreBundle, repo, digest)
	if err != nil {
		return nil, err
	}

	predicate := bundle.Statement.Predicate

	measurements := make(map[string]TDXMeasurement)
	for k, v := range predicate.Fields {
		structValue := v.GetStructValue()
		if structValue == nil {
			continue
		}

		fields := structValue.Fields
		measurements[k] = TDXMeasurement{
			MRTD:  fields["mrtd"].GetStringValue(),
			RTMR0: fields["rtmr0"].GetStringValue(),
			RTMR1: fields["rtmr1"].GetStringValue(),
			RTMR2: fields["rtmr2"].GetStringValue(),
		}
	}
	return measurements, nil
}
