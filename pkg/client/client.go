package client

import (
	"bytes"
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
func (s *SecureClient) Verify() (*EnclaveState, error) {
	_, eifHash, err := github.FetchLatestRelease(s.repo)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch latest release: %v", err)
	}

	sigstoreBundle, err := github.FetchAttestationBundle(s.repo, eifHash)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch attestation bundle: %v", err)
	}

	sigstoreTrustRoot, err := sigstore.FetchTrustRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch trust root: %v", err)
	}

	codeMeasurements, err := sigstore.VerifyMeasurementAttestation(
		sigstoreTrustRoot, sigstoreBundle,
		eifHash, s.repo,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to verify attested measurements: %v", err)
	}

	enclaveAttestation, enclaveCertFP, err := attestation.Fetch(s.enclave)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch enclave measurements: %v", err)
	}
	enclaveMeasurements, attestedCertFP, err := enclaveAttestation.Verify()
	if err != nil {
		return nil, fmt.Errorf("failed to verify enclave measurements: %v", err)
	}

	if !bytes.Equal(enclaveCertFP, attestedCertFP) {
		return nil, ErrCertMismatch
	}

	err = codeMeasurements.Equals(enclaveMeasurements)
	if err == nil {
		s.verifiedState = &EnclaveState{
			CertFingerprint: attestedCertFP,
			EIFHash:         eifHash,
		}
	}
	return s.verifiedState, err
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

func (s *SecureClient) makeRequest(req *http.Request) (*Response, error) {
	resp, err := s.HTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	return toResponse(resp)
}

// Post makes an HTTP POST request
func (s *SecureClient) Post(url string, headers map[string]string, body []byte) (*Response, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return s.makeRequest(req)
}

// Get makes a HTTP GET request
func (s *SecureClient) Get(url string, headers map[string]string) (*Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return s.makeRequest(req)
}
