package sigstore

import (
	"encoding/hex"
	"fmt"
	"os"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/tinfoilanalytics/verifier/pkg/models"
)

const (
	OidcIssuer = "https://token.actions.githubusercontent.com"
)

// VerifyAttestedMeasurements verifies the attested measurements of an EIF measurement
// against a trusted root (Sigstore) and returns the measurement payload contained in the DSSE.
func VerifyAttestedMeasurements(trustedRootJSON, bundleJSON []byte, hexDigest, repo string) (*models.Measurements, error) {
	trustedMaterial, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing trusted root: %w", err)
	}

	var b bundle.Bundle
	b.Bundle = new(protobundle.Bundle)
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("parsing bundle: %w", err)
	}

	sev, err := verify.NewSignedEntityVerifier(
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
		"^https://github.com/"+repo+"/.github/workflows/release.yml@refs/tags/*",
	)
	if err != nil {
		return nil, fmt.Errorf("creating certificate identity: %w", err)
	}

	digest, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, fmt.Errorf("decoding hex digest: %w", err)
	}
	result, err := sev.Verify(&b, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digest),
		verify.WithCertificateIdentity(certID)),
	)
	if err != nil {
		return nil, fmt.Errorf("verifying: %w", err)
	}

	predicate := result.Statement.Predicate.GetFields()

	return &models.Measurements{
		PCR0: predicate["PCR0"].GetStringValue(),
		PCR1: predicate["PCR1"].GetStringValue(),
		PCR2: predicate["PCR2"].GetStringValue(),
	}, nil
}

// FetchTrustRoot downloads the Sigstore trust root configuration and saves it as a JSON file
func FetchTrustRoot() error {
	opts := tuf.DefaultOptions()
	client, err := tuf.New(opts)
	if err != nil {
		return err
	}

	rootJSON, err := client.GetTarget("trusted_root.json")
	if err != nil {
		return err
	}

	if err := os.WriteFile("trusted_root.json", rootJSON, 0644); err != nil {
		return err
	}

	return nil
}
