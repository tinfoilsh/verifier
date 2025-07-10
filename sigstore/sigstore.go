package sigstore

import (
	_ "embed"
	"encoding/hex"
	"fmt"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/tinfoilsh/verifier/attestation"
)

const (
	oidcIssuer = "https://token.actions.githubusercontent.com"
)

type Client struct {
	trustRoot *root.TrustedRoot
}

func NewClient() (*Client, error) {
	trustRootJSON, err := FetchTrustRoot()
	if err != nil {
		return nil, fmt.Errorf("fetching trust root: %w", err)
	}

	trustRoot, err := root.NewTrustedRootFromJSON(trustRootJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing trust root: %w", err)
	}

	return &Client{
		trustRoot: trustRoot,
	}, nil
}

// FetchTrustRoot fetches the trust root from the Sigstore TUF repo
func FetchTrustRoot() ([]byte, error) {
	tufOpts := tuf.
		DefaultOptions().
		WithDisableLocalCache()
	//WithFetcher(util.NewFetcher())
	client, err := tuf.New(tufOpts)
	if err != nil {
		return nil, err
	}

	return client.GetTarget("trusted_root.json")
}

func (c *Client) verifyBundle(bundleJSON []byte, repo, hexDigest string) (*verify.VerificationResult, error) {
	var b bundle.Bundle
	b.Bundle = new(protobundle.Bundle)
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("parsing bundle: %w", err)
	}

	verifier, err := verify.NewSignedEntityVerifier(
		c.trustRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("creating signed entity verifier: %w", err)
	}

	certID, err := verify.NewShortCertificateIdentity(
		oidcIssuer,
		"",
		"",
		// TODO: Can we pin this to latest without fetching the latest release?
		"^https://github.com/"+repo+"/.github/workflows/.*@refs/tags/*",
	)
	if err != nil {
		return nil, fmt.Errorf("creating certificate identity: %w", err)
	}

	digest, err := hex.DecodeString(hexDigest)
	if err != nil {
		return nil, fmt.Errorf("decoding hex digest: %w", err)
	}
	result, err := verifier.Verify(
		&b,
		verify.NewPolicy(
			verify.WithArtifactDigest("sha256", digest),
			verify.WithCertificateIdentity(certID),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("verifying: %w", err)
	}

	return result, nil
}

func (c *Client) VerifyAttestation(
	bundleJSON []byte,
	hexDigest, repo string,
) (*attestation.Measurement, error) {
	result, err := c.verifyBundle(bundleJSON, repo, hexDigest)
	if err != nil {
		return nil, fmt.Errorf("verifying bundle: %w", err)
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
	case attestation.SevGuestV1:
		return &attestation.Measurement{
			Type:      measurementType,
			Registers: []string{predicateFields["measurement"].GetStringValue()},
		}, nil
	case attestation.SnpTdxMultiPlatformV1:
		tdxMeasurement := predicateFields["tdx_measurement"].GetStructValue()
		if tdxMeasurement == nil {
			return nil, fmt.Errorf("invalid multiplatform measurement: no tdx measurement")
		}
		rtmrs := tdxMeasurement.GetFields()

		return &attestation.Measurement{
			Type: measurementType,
			Registers: []string{
				predicateFields["snp_measurement"].GetStringValue(),
				rtmrs["rtmr1"].GetStringValue(),
				rtmrs["rtmr2"].GetStringValue(),
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported predicate type: %s", result.Statement.PredicateType)
	}
}

// VerifyAttestation verifies the attested measurements of an enclave image
// against a trusted root (Sigstore) and returns the measurement payload contained in the DSSE.
// Deprecated: Use client.VerifyAttestation instead.
func VerifyAttestation(
	trustRootJSON, bundleJSON []byte,
	hexDigest, repo string,
) (*attestation.Measurement, error) {
	trustRoot, err := root.NewTrustedRootFromJSON(trustRootJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing trust root: %w", err)
	}
	client := &Client{trustRoot: trustRoot}
	return client.VerifyAttestation(bundleJSON, hexDigest, repo)
}
