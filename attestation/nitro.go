package attestation

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/blocky/nitrite"
)

var (
	NitroEnclaveVerifierOpts = nitrite.VerifyOptions{}
)

// verifyNitroAttestation decodes a base64 encoded attestation document,
// verifies it against the AWS root, and returns the inner measurements and user data.
func verifyNitroAttestation(attestationDoc string) (*Verification, error) {
	attDocBytes, err := base64.StdEncoding.DecodeString(attestationDoc)
	if err != nil {
		return nil, err
	}
	attestedResult, err := nitrite.Verify(attDocBytes, NitroEnclaveVerifierOpts)
	if err != nil {
		return nil, err
	}

	pcrs := attestedResult.Document.PCRs
	measurement := NewNitroMeasurement(
		hex.EncodeToString(pcrs[0]),
		hex.EncodeToString(pcrs[1]),
		hex.EncodeToString(pcrs[2]),
	)

	return &Verification{
		Measurement: measurement,
		PublicKeyFP: string(attestedResult.Document.UserData),
	}, nil
}
