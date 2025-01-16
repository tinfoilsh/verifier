package client

import (
	"fmt"
	"net/http"

	"github.com/tinfoilanalytics/verifier/pkg/attestation"
	"github.com/tinfoilanalytics/verifier/pkg/github"
	"github.com/tinfoilanalytics/verifier/pkg/sigstore"
)

type EnclaveState struct {
	CertFingerprint []byte
	EIFHash         string
}

type SecureClient struct {
	enclave, repo string

	verifiedState *EnclaveState
}

func NewSecureClient(enclave, repo string) *SecureClient {
	return &SecureClient{
		enclave: enclave,
		repo:    repo,
	}
}

// Verify verifies the enclave against the latest code release
func (s *SecureClient) Verify() error {
	_, eifHash, err := github.FetchLatestRelease(s.repo)
	if err != nil {
		return fmt.Errorf("failed to fetch latest release: %v", err)
	}

	sigstoreBundle, err := github.FetchAttestationBundle(s.repo, eifHash)
	if err != nil {
		return fmt.Errorf("failed to fetch attestation bundle: %v", err)
	}

	sigstoreTrustRoot, err := sigstore.FetchTrustRoot()
	if err != nil {
		return fmt.Errorf("failed to fetch trust root: %v", err)
	}

	codeMeasurements, err := sigstore.VerifyMeasurementAttestation(
		sigstoreTrustRoot, sigstoreBundle,
		eifHash, s.repo,
	)
	if err != nil {
		return fmt.Errorf("failed to verify attested measurements: %v", err)
	}

	enclaveAttestation, err := attestation.Fetch(s.enclave)
	if err != nil {
		return fmt.Errorf("failed to fetch enclave measurements: %v", err)
	}
	enclaveMeasurements, certFP, err := enclaveAttestation.Verify()
	if err != nil {
		return fmt.Errorf("failed to verify enclave measurements: %v", err)
	}

	err = codeMeasurements.Equals(enclaveMeasurements)
	if err == nil {
		s.verifiedState = &EnclaveState{
			CertFingerprint: certFP,
			EIFHash:         eifHash,
		}
	}
	return err
}

// VerificationState returns the last verified enclave state
func (s *SecureClient) VerificationState() *EnclaveState {
	return s.verifiedState
}

// HTTPClient returns an HTTP client that only accepts TLS connections to the verified enclave
func (s *SecureClient) HTTPClient() *http.Client {
	return &http.Client{
		Transport: &TLSBoundRoundTripper{s.verifiedState.CertFingerprint},
	}
}
