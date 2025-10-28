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
	"github.com/tinfoilsh/verifier/github"
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

func NewClientFromJSON(trustRootJSON []byte) (*Client, error) {
	trustRoot, err := root.NewTrustedRootFromJSON(trustRootJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing trust root: %w", err)
	}
	return &Client{trustRoot: trustRoot}, nil
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

func (c *Client) VerifyBundle(bundleJSON []byte, repo, hexDigest string) (*verify.VerificationResult, error) {
	if c.trustRoot == nil {
		return nil, fmt.Errorf("trust root is not set")
	}

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
	result, err := c.VerifyBundle(bundleJSON, repo, hexDigest)
	if err != nil {
		return nil, fmt.Errorf("verifying bundle: %w", err)
	}

	predicate := result.Statement.Predicate
	predicateFields := predicate.Fields

	measurementType := attestation.PredicateType(result.Statement.PredicateType)
	switch measurementType {
	case attestation.SevGuestV1:
		return &attestation.Measurement{
			Type:      measurementType,
			Registers: []string{predicateFields["measurement"].GetStringValue()},
		}, nil
	case attestation.SnpTdxMultiPlatformV1:
		tdxMeasurementField, ok := predicateFields["tdx_measurement"]
		if !ok {
			return nil, fmt.Errorf("invalid multiplatform measurement: no tdx measurement")
		}
		if tdxMeasurementField == nil {
			return nil, fmt.Errorf("invalid multiplatform measurement: tdx measurement is nil")
		}
		tdxMeasurement := tdxMeasurementField.GetStructValue()
		if tdxMeasurement == nil {
			return nil, fmt.Errorf("invalid multiplatform measurement: tdx measurement is not a struct")
		}
		rtmrs := tdxMeasurement.GetFields()

		// Validate multiplatform measurement format
		snpMeasurement, ok := predicateFields["snp_measurement"]
		if !ok {
			return nil, fmt.Errorf("invalid multiplatform measurement: no snp measurement")
		}
		if snpMeasurement == nil {
			return nil, fmt.Errorf("invalid multiplatform measurement: snp measurement is nil")
		}

		for _, rtmr := range []string{"rtmr1", "rtmr2"} {
			v, ok := rtmrs[rtmr]
			if !ok {
				return nil, fmt.Errorf("invalid multiplatform measurement: no %s", rtmr)
			}
			if v == nil {
				return nil, fmt.Errorf("invalid multiplatform measurement: %s is nil", rtmr)
			}
		}

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

// FetchHardwareMeasurements fetches the MRTD and RTMR0 from a given hardware repo
func (c *Client) FetchHardwareMeasurements(repo, digest string) ([]*attestation.HardwareMeasurement, error) {
	sigstoreBundle, err := github.FetchAttestationBundle(repo, digest)
	if err != nil {
		return nil, err
	}

	bundle, err := c.VerifyBundle(sigstoreBundle, repo, digest)
	if err != nil {
		return nil, err
	}

	predicate := bundle.Statement.Predicate
	predicateType := bundle.Statement.PredicateType

	if attestation.PredicateType(predicateType) != attestation.HardwareMeasurementsV1 {
		return nil, fmt.Errorf("unexpected predicate type: %s", predicateType)
	}

	var measurements []*attestation.HardwareMeasurement
	for k, v := range predicate.Fields {
		structValue := v.GetStructValue()
		if structValue == nil {
			return nil, fmt.Errorf("invalid hardware measurement")
		}

		fields := structValue.Fields

		for _, field := range []string{"mrtd", "rtmr0"} {
			v, ok := fields[field]
			if !ok {
				return nil, fmt.Errorf("invalid hardware measurement: no %s", field)
			}
			if v == nil {
				return nil, fmt.Errorf("invalid hardware measurement: %s is nil", field)
			}
		}

		measurements = append(measurements, &attestation.HardwareMeasurement{
			ID:    fmt.Sprintf("%s@%s", k, digest),
			MRTD:  fields["mrtd"].GetStringValue(),
			RTMR0: fields["rtmr0"].GetStringValue(),
		})
	}
	return measurements, nil
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

// LatestHardwareMeasurements fetches the latest hardware measurements from GitHub+Sigstore
func (c *Client) LatestHardwareMeasurements() ([]*attestation.HardwareMeasurement, error) {
	const repo = "tinfoilsh/hardware-measurements"
	digest, err := github.FetchLatestDigest(repo)
	if err != nil {
		return nil, err
	}

	return c.FetchHardwareMeasurements(repo, digest)
}
