package client

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/tinfoilsh/verifier/attestation"
	"github.com/tinfoilsh/verifier/github"
	"github.com/tinfoilsh/verifier/sigstore"
)

// GroundTruth represents the "known good" verified of the enclave
type GroundTruth struct {
	PublicKey          string
	Digest             string
	CodeMeasurement    *attestation.Measurement
	EnclaveMeasurement *attestation.Measurement
}

type SecureClient struct {
	enclave, repo string

	groundTruth *GroundTruth
}

func NewSecureClient(enclave, repo string) *SecureClient {
	return &SecureClient{
		enclave: enclave,
		repo:    repo,
	}
}

// Enclave returns the enclave URL
func (s *SecureClient) Enclave() string {
	return s.enclave
}

// Repo returns the repository URL
func (s *SecureClient) Repo() string {
	return s.repo
}

// GroundTruth returns the last verified enclave state
func (s *SecureClient) GroundTruth() *GroundTruth {
	return s.groundTruth
}

// Verify fetches the latest verification information from GitHub and Sigstore and stores the ground truth results in the client
func (s *SecureClient) Verify() (*GroundTruth, error) {
	digest, err := github.FetchLatestDigest(s.repo)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch latest release: %v", err)
	}

	sigstoreClient, err := sigstore.NewClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create sigstore client: %v", err)
	}

	sigstoreBundle, err := github.FetchAttestationBundle(s.repo, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch attestation bundle: %v", err)
	}

	codeMeasurement, err := sigstoreClient.VerifyAttestation(sigstoreBundle, digest, s.repo)
	if err != nil {
		return nil, fmt.Errorf("failed to verify attested measurements: %v", err)
	}

	enclaveAttestation, err := attestation.Fetch(s.enclave)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch enclave measurements: %v", err)
	}
	enclaveVerification, err := enclaveAttestation.Verify()
	if err != nil {
		return nil, fmt.Errorf("failed to verify enclave measurements: %v", err)
	}

	// Fetch hardware platform measurements if required
	if enclaveAttestation.Format == attestation.TdxGuestV1 {
		hwMeasurements, err := sigstoreClient.LatestHardwareMeasurements()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch TDX platform measurements: %v", err)
		}
		_, err = attestation.VerifyHardware(hwMeasurements, enclaveVerification.Measurement)
		if err != nil {
			return nil, fmt.Errorf("failed to verify hardware measurements: %v", err)
		}
	}

	// Get cert from TLS connection
	var addr string
	if strings.Contains(s.enclave, ":") {
		// Enclave already has a port specified
		addr = s.enclave
	} else {
		// Append default HTTPS port
		addr = s.enclave + ":443"
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to enclave: %v", err)
	}
	defer conn.Close()
	certFP, err := attestation.ConnectionCertFP(conn.ConnectionState())
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate fingerprint: %v", err)
	}

	// Check if the certificate fingerprint matches the one in the verification
	if certFP != enclaveVerification.PublicKeyFP {
		return nil, fmt.Errorf("certificate fingerprint mismatch: expected %s, got %s", enclaveVerification.PublicKeyFP, certFP)
	}

	if err = codeMeasurement.Equals(enclaveVerification.Measurement); err != nil {
		return nil, err
	}

	s.groundTruth = &GroundTruth{
		PublicKey:          enclaveVerification.PublicKeyFP,
		Digest:             digest,
		CodeMeasurement:    codeMeasurement,
		EnclaveMeasurement: enclaveVerification.Measurement,
	}
	return s.groundTruth, err
}

// HTTPClient returns an HTTP client that only accepts TLS connections to the verified enclave
func (s *SecureClient) HTTPClient() (*http.Client, error) {
	if s.groundTruth == nil {
		_, err := s.Verify()
		if err != nil {
			return nil, fmt.Errorf("failed to verify enclave: %v", err)
		}
	}

	return &http.Client{
		Transport: &TLSBoundRoundTripper{s.groundTruth.PublicKey},
	}, nil
}

func (s *SecureClient) makeRequest(req *http.Request) (*Response, error) {
	httpClient, err := s.HTTPClient()
	if err != nil {
		return nil, err
	}

	// If URL doesn't start with anything, assume it's a relative path and set the base URL
	if req.URL.Host == "" {
		req.URL.Scheme = "https"
		req.URL.Host = s.enclave
	}

	resp, err := httpClient.Do(req)
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

// Get makes an HTTP GET request
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
