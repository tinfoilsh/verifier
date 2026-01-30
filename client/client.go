package client

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/tinfoilsh/verifier/attestation"
	"github.com/tinfoilsh/verifier/github"
	"github.com/tinfoilsh/verifier/sigstore"
	"github.com/tinfoilsh/verifier/util"
)

const (
	pinnedNoRepo   = "pinned_no_repo"
	pinnedNoDigest = "pinned_no_digest"
)

//go:embed trusted_root.json
var embeddedTrustedRoot []byte

// GroundTruth represents the "known good" verified of the enclave
type GroundTruth struct {
	EnclaveHost         string                           `json:"enclave_host,omitempty"`
	TLSPublicKey        string                           `json:"tls_public_key,omitempty"`
	HPKEPublicKey       string                           `json:"hpke_public_key,omitempty"`
	Digest              string                           `json:"digest"`
	CodeMeasurement     *attestation.Measurement         `json:"code_measurement"`
	EnclaveMeasurement  *attestation.Measurement         `json:"enclave_measurement"`
	HardwareMeasurement *attestation.HardwareMeasurement `json:"hardware_measurement,omitempty"`
	CodeFingerprint     string                           `json:"code_fingerprint"`
	EnclaveFingerprint  string                           `json:"enclave_fingerprint"`
}

type SecureClient struct {
	enclave, repo string

	// Pinned measurement mode
	codeMeasurement      *attestation.Measurement
	hardwareMeasurements []*attestation.HardwareMeasurement

	groundTruth    *GroundTruth
	sigstoreClient *sigstore.Client
}

var (
	defaultRouterRepo = "tinfoilsh/confidential-model-router"
	defaultRouterURL  = "https://atc.tinfoil.sh/routers"
	defaultClient     = NewSecureClient("inference.tinfoil.sh", defaultRouterRepo)
)

func fetchRouters() ([]string, error) {
	resp, _, err := util.Get(defaultRouterURL)
	if err != nil {
		return nil, err
	}

	var routers []string
	if err := json.Unmarshal(resp, &routers); err != nil {
		return nil, err
	}

	return routers, nil
}

// NewSecureClient creates a new secure client with a given repo and enclave
func NewSecureClient(enclave, repo string) *SecureClient {
	return &SecureClient{
		enclave: enclave,
		repo:    repo,
	}
}

// NewPinnedSecureClient creates a new secure client with a given enclave and fixed measurements
func NewPinnedSecureClient(enclave string, codeMeasurement *attestation.Measurement, hardwareMeasurements []*attestation.HardwareMeasurement) *SecureClient {
	return &SecureClient{
		enclave:              enclave,
		repo:                 pinnedNoRepo,
		codeMeasurement:      codeMeasurement,
		hardwareMeasurements: hardwareMeasurements,
	}
}

// NewDefaultSecureClient creates a new secure client with fallback mechanism.
// It tries to fetch routers from the router service, attempts to verify each one,
// and falls back to inference.tinfoil.sh if all routers fail.
func NewDefaultClient() (*SecureClient, error) {
	routers, err := fetchRouters()
	if err != nil {
		// If we can't get routers, fall back to inference.tinfoil.sh immediately
		return defaultClient, nil
	}

	// Try each router in sequence
	for _, routerURL := range routers {
		client := NewSecureClient(routerURL, defaultRouterRepo)

		// Return first working router
		_, err := client.Verify()
		if err == nil {
			return client, nil
		}
	}

	return defaultClient, nil
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

// GroundTruthJSON returns the ground truth as a JSON string
func (s *SecureClient) GroundTruthJSON() (string, error) {
	encoded, err := json.Marshal(s.groundTruth)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func (s *SecureClient) getSigstoreClient() (*sigstore.Client, error) {
	if s.sigstoreClient == nil {
		var err error
		s.sigstoreClient, err = sigstore.NewClient()
		if err != nil {
			return nil, fmt.Errorf("failed to create sigstore client: %v", err)
		}
	}
	return s.sigstoreClient, nil
}

// Verify fetches the latest verification information from GitHub and Sigstore and stores the ground truth results in the client
func (s *SecureClient) Verify() (*GroundTruth, error) {
	var codeMeasurement = s.codeMeasurement
	var digest = pinnedNoDigest
	if s.codeMeasurement == nil {
		var err error
		digest, err = github.FetchLatestDigest(s.repo)
		if err != nil {
			return nil, fmt.Errorf("fetchDigest: failed to fetch latest release: %v", err)
		}

		sigstoreClient, err := s.getSigstoreClient()
		if err != nil {
			return nil, fmt.Errorf("verifyCode: failed to create sigstore client: %v", err)
		}

		sigstoreBundle, err := github.FetchAttestationBundle(s.repo, digest)
		if err != nil {
			return nil, fmt.Errorf("verifyCode: failed to fetch attestation bundle: %v", err)
		}

		codeMeasurement, err = sigstoreClient.VerifyAttestation(sigstoreBundle, s.repo, digest)
		if err != nil {
			return nil, fmt.Errorf("verifyCode: failed to verify attested measurements: %v", err)
		}
	}

	enclaveAttestation, err := attestation.Fetch(s.enclave)
	if err != nil {
		return nil, fmt.Errorf("verifyEnclave: failed to fetch enclave measurements: %v", err)
	}
	enclaveVerification, err := enclaveAttestation.Verify()
	if err != nil {
		return nil, fmt.Errorf("verifyEnclave: failed to verify enclave measurements: %v", err)
	}

	// Fetch hardware platform measurements if required
	var matchedHwMeasurement *attestation.HardwareMeasurement
	if enclaveAttestation.Format == attestation.TdxGuestV2 {
		var hwMeasurements = s.hardwareMeasurements
		if len(s.hardwareMeasurements) == 0 {
			sigstoreClient, err := s.getSigstoreClient()
			if err != nil {
				return nil, fmt.Errorf("verifyHardware: failed to create sigstore client: %v", err)
			}
			hwMeasurements, err = sigstoreClient.LatestHardwareMeasurements()
			if err != nil {
				return nil, fmt.Errorf("verifyHardware: failed to fetch TDX platform measurements: %v", err)
			}
		}

		matchedHwMeasurement, err = attestation.VerifyHardware(hwMeasurements, enclaveVerification.Measurement)
		if err != nil {
			return nil, fmt.Errorf("verifyHardware: failed to verify hardware measurements: %v", err)
		}
	}

	if err := enclaveValidPubKey(s.enclave, enclaveVerification); err != nil {
		return nil, fmt.Errorf("validateTLS: %v", err)
	}

	if err = codeMeasurement.Equals(enclaveVerification.Measurement); err != nil {
		return nil, fmt.Errorf("measurements: %v", err)
	}

	codeFingerprint, err := attestation.Fingerprint(codeMeasurement, matchedHwMeasurement, enclaveVerification.Measurement.Type)
	if err != nil {
		return nil, fmt.Errorf("measurements: failed to compute code fingerprint: %v", err)
	}
	enclaveFingerprint, err := attestation.Fingerprint(enclaveVerification.Measurement, matchedHwMeasurement, enclaveVerification.Measurement.Type)
	if err != nil {
		return nil, fmt.Errorf("measurements: failed to compute enclave fingerprint: %v", err)
	}

	s.groundTruth = &GroundTruth{
		EnclaveHost:         s.enclave,
		TLSPublicKey:        enclaveVerification.TLSPublicKeyFP,
		HPKEPublicKey:       enclaveVerification.HPKEPublicKey,
		Digest:              digest,
		HardwareMeasurement: matchedHwMeasurement,
		CodeMeasurement:     codeMeasurement,
		EnclaveMeasurement:  enclaveVerification.Measurement,
		CodeFingerprint:     codeFingerprint,
		EnclaveFingerprint:  enclaveFingerprint,
	}
	return s.groundTruth, nil
}

// VerifyFromBundle verifies using a pre-fetched attestation bundle from ATC (single-request verification)
func (s *SecureClient) VerifyFromBundle(bundle *attestation.Bundle) (*GroundTruth, error) {
	sigstoreClient, err := s.getSigstoreClient()
	if err != nil {
		return nil, fmt.Errorf("verifyCode: failed to create sigstore client: %v", err)
	}

	codeMeasurement, err := sigstoreClient.VerifyAttestation(bundle.SigstoreBundle, s.repo, bundle.Digest)
	if err != nil {
		return nil, fmt.Errorf("verifyCode: failed to verify attested measurements: %v", err)
	}

	// Decode VCEK from base64 DER format
	vcekDER, err := base64.StdEncoding.DecodeString(bundle.VCEK)
	if err != nil {
		return nil, fmt.Errorf("verifyEnclave: failed to decode VCEK certificate: %v", err)
	}

	enclaveVerification, err := bundle.EnclaveAttestationReport.VerifyWithVCEK(vcekDER)
	if err != nil {
		return nil, fmt.Errorf("verifyEnclave: failed to verify enclave measurements: %v", err)
	}

	if err = codeMeasurement.Equals(enclaveVerification.Measurement); err != nil {
		return nil, fmt.Errorf("measurements: %v", err)
	}

	codeFingerprint, err := attestation.Fingerprint(codeMeasurement, nil, enclaveVerification.Measurement.Type)
	if err != nil {
		return nil, fmt.Errorf("measurements: failed to compute code fingerprint: %v", err)
	}
	enclaveFingerprint, err := attestation.Fingerprint(enclaveVerification.Measurement, nil, enclaveVerification.Measurement.Type)
	if err != nil {
		return nil, fmt.Errorf("measurements: failed to compute enclave fingerprint: %v", err)
	}

	// Verify enclave certificate
	if bundle.EnclaveCert == "" {
		return nil, fmt.Errorf("verifyCertificate: enclave certificate is required")
	}
	_, err = attestation.VerifyCertificate(
		bundle.EnclaveCert,
		bundle.Domain,
		bundle.EnclaveAttestationReport,
		enclaveVerification.HPKEPublicKey,
	)
	if err != nil {
		return nil, fmt.Errorf("verifyCertificate: %v", err)
	}

	s.enclave = bundle.Domain
	s.groundTruth = &GroundTruth{
		EnclaveHost:        bundle.Domain,
		TLSPublicKey:       enclaveVerification.TLSPublicKeyFP,
		HPKEPublicKey:      enclaveVerification.HPKEPublicKey,
		Digest:             bundle.Digest,
		CodeMeasurement:    codeMeasurement,
		EnclaveMeasurement: enclaveVerification.Measurement,
		CodeFingerprint:    codeFingerprint,
		EnclaveFingerprint: enclaveFingerprint,
	}
	return s.groundTruth, nil
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
		Transport: &TLSBoundRoundTripper{s.groundTruth.TLSPublicKey},
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

// VerifyJSON verifies an enclave against a repo and returns the verification data as a JSON string
func VerifyJSON(enclave, repo string, sigstoreTrustedRootJSON []byte) (string, error) {
	sigstoreClient, err := getSigstoreClient(sigstoreTrustedRootJSON)
	if err != nil {
		return "", fmt.Errorf("failed to create sigstore client: %v", err)
	}

	client := &SecureClient{
		enclave:        enclave,
		repo:           repo,
		sigstoreClient: sigstoreClient,
	}
	_, err = client.Verify()
	if err != nil {
		return "", err
	}
	return client.GroundTruthJSON()
}

func getSigstoreClient(sigstoreTrustedRootJSON []byte) (*sigstore.Client, error) {
	var trustedRootJSON []byte
	var err error

	if len(sigstoreTrustedRootJSON) > 0 {
		trustedRootJSON = sigstoreTrustedRootJSON
	} else if len(embeddedTrustedRoot) > 0 {
		trustedRootJSON = embeddedTrustedRoot
	} else {
		trustedRootJSON, err = sigstore.FetchTrustRoot()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch trusted root: %v", err)
		}
	}

	return sigstore.NewClientFromJSON(trustedRootJSON)
}

func verifyBundle(bundle *attestation.Bundle, repo string, sigstoreTrustedRootJSON []byte) (string, error) {
	sigstoreClient, err := getSigstoreClient(sigstoreTrustedRootJSON)
	if err != nil {
		return "", fmt.Errorf("failed to create sigstore client: %v", err)
	}

	client := &SecureClient{
		enclave:        bundle.Domain,
		repo:           repo,
		sigstoreClient: sigstoreClient,
	}
	_, err = client.VerifyFromBundle(bundle)
	if err != nil {
		return "", err
	}
	return client.GroundTruthJSON()
}

// VerifyFromBundleJSON verifies using a pre-fetched attestation bundle and returns the verification data as a JSON string
func VerifyFromBundleJSON(bundleJSON []byte, repo string, sigstoreTrustedRootJSON []byte) (string, error) {
	var bundle attestation.Bundle
	if err := json.Unmarshal(bundleJSON, &bundle); err != nil {
		return "", fmt.Errorf("failed to parse bundle: %v", err)
	}
	return verifyBundle(&bundle, repo, sigstoreTrustedRootJSON)
}

// VerifyFromATCJSON fetches an attestation bundle from the default ATC endpoint and verifies it.
// Returns the verification data as a JSON string.
func VerifyFromATCJSON(repo string, sigstoreTrustedRootJSON []byte) (string, error) {
	return VerifyFromATCURLJSON("", repo, sigstoreTrustedRootJSON)
}

// VerifyFromATCURLJSON fetches an attestation bundle from a custom URL and verifies it.
// If attestationBundleURL is empty, defaults to https://atc.tinfoil.sh.
// Returns the verification data as a JSON string.
func VerifyFromATCURLJSON(attestationBundleURL, repo string, sigstoreTrustedRootJSON []byte) (string, error) {
	var bundle *attestation.Bundle
	var err error

	if attestationBundleURL == "" {
		bundle, err = attestation.FetchBundle()
	} else {
		bundle, err = attestation.FetchBundleFrom(attestationBundleURL)
	}
	if err != nil {
		return "", fmt.Errorf("failed to fetch bundle: %v", err)
	}

	return verifyBundle(bundle, repo, sigstoreTrustedRootJSON)
}
