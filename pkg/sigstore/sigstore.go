package sigstore

import (
	"encoding/hex"
	"fmt"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/tinfoilanalytics/verifier/pkg/attestation"
)

const (
	OidcIssuer = "https://token.actions.githubusercontent.com"
)

// VerifyMeasurementAttestation verifies the attested measurements of an EIF measurement
// against a trusted root (Sigstore) and returns the measurement payload contained in the DSSE.
func VerifyMeasurementAttestation(
	trustedRootJSON, bundleJSON []byte,
	hexDigest, repo string,
) (*attestation.Measurement, error) {
	trustedMaterial, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing trusted root: %w", err)
	}

	var b bundle.Bundle
	b.Bundle = new(protobundle.Bundle)
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("parsing bundle: %w", err)
	}

	verifier, err := verify.NewSignedEntityVerifier(
		trustedMaterial,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("creating signed entity verifier: %w", err)
	}

	certID, err := verify.NewShortCertificateIdentity(
		OidcIssuer,
		"",
		"",
		// TODO: Can we pin this to latest without fetching the latest release?
		"^https://github.com/"+repo+"/.github/workflows/release.yml@refs/tags/*",
	)
	if err != nil {
		return nil, fmt.Errorf("creating certificate identity: %w", err)
	}

	digest, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, fmt.Errorf("decoding hex digest: %w", err)
	}
	result, err := verifier.Verify(&b, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digest),
		verify.WithCertificateIdentity(certID)),
	)
	if err != nil {
		return nil, fmt.Errorf("verifying: %w", err)
	}

	predicate := result.Statement.Predicate
	predicateFields := predicate.Fields

	measurementType := attestation.PredicateType(result.Statement.PredicateType)
	switch measurementType {
	case attestation.AWSNitroEnclaveV1:
		return &attestation.Measurement{
			Type: measurementType,
			Registers: []string{
				predicateFields["PCR0"].GetStringValue(),
				predicateFields["PCR1"].GetStringValue(),
				predicateFields["PCR2"].GetStringValue(),
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported predicate type: %s", result.Statement.PredicateType)
	}
}

// FetchTrustRoot fetches the trust root from the Sigstore TUF repo
func FetchTrustRoot() ([]byte, error) {
	tufOpts := tuf.DefaultOptions()
	tufOpts.DisableLocalCache = true
	client, err := tuf.New(tufOpts)
	if err != nil {
		return nil, err
	}

	return client.GetTarget("trusted_root.json")
}
