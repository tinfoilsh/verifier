package attestation

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

type PredicateType string

const (
	AWSNitroEnclaveV1 PredicateType = "https://tinfoil.sh/predicate/aws-nitro-enclave/v1"
	SevGuestV1        PredicateType = "https://tinfoil.sh/predicate/sev-snp-guest/v1"
	TdxGuestV1        PredicateType = "https://tinfoil.sh/predicate/tdx-guest/v1"

	attestationEndpoint = "/.well-known/tinfoil-attestation"
)

var (
	ErrFormatMismatch      = errors.New("attestation format mismatch")
	ErrMeasurementMismatch = errors.New("measurement mismatch")
)

type Measurement struct {
	Type      PredicateType
	Registers []string
}

type Verification struct {
	Measurement *Measurement
	PublicKeyFP string
}

// Fingerprint computes the SHA-256 hash of all measurements, or returns the single measurement if there is only one
func (m *Measurement) Fingerprint() string {
	if len(m.Registers) == 1 {
		return m.Registers[0]
	}

	all := string(m.Type) + strings.Join(m.Registers, "")
	return fmt.Sprintf("%x", sha256.Sum256([]byte(all)))
}

func (m *Measurement) Equals(other *Measurement) error {
	if m.Type != other.Type {
		return ErrFormatMismatch
	}
	if len(m.Registers) != len(other.Registers) || !slices.Equal(m.Registers, other.Registers) {
		return ErrMeasurementMismatch
	}

	return nil
}

// Document represents an attestation document
type Document struct {
	Format PredicateType `json:"format"`
	Body   string        `json:"body"`
}

// Hash returns the SHA-256 hash of the attestation document
func (d *Document) Hash() string {
	all := string(d.Format) + d.Body
	return fmt.Sprintf("%x", sha256.Sum256([]byte(all)))
}

// Verify checks the attestation document against its trust root and returns the inner measurements
func (d *Document) Verify() (*Verification, error) {
	switch d.Format {
	case AWSNitroEnclaveV1:
		return verifyNitroAttestation(d.Body)
	case SevGuestV1:
		return verifySevAttestation(d.Body)
	case TdxGuestV1:
		return verifyTdxAttestation(d.Body)
	default:
		return nil, fmt.Errorf("unsupported attestation format: %s", d.Format)
	}
}

// VerifyAttestationJSON verifies an attestation document in JSON format and returns the inner measurements
func VerifyAttestationJSON(j []byte) (*Verification, error) {
	var doc Document
	err := json.Unmarshal(j, &doc)
	if err != nil {
		return nil, err
	}

	return doc.Verify()
}

// KeyFP returns the fingerprint of a given ECDSA public key
func KeyFP(publicKey *ecdsa.PublicKey) string {
	bytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:])
}

// CertPubkeyFP returns the fingerprint of the public key of a given certificate
func CertPubkeyFP(cert *x509.Certificate) (string, error) {
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("unsupported public key type: %T", cert.PublicKey)
	}

	return KeyFP(pubKey), nil
}

// ConnectionCertFP gets the KeyFP of the public key of a TLS connection state
func ConnectionCertFP(c tls.ConnectionState) (string, error) {
	if len(c.PeerCertificates) == 0 {
		return "", fmt.Errorf("no peer certificates")
	}
	cert := c.PeerCertificates[0]
	return CertPubkeyFP(cert)
}

// Fetch retrieves the attestation document from a given enclave hostname
func Fetch(host string) (*Document, error) {
	var u url.URL
	u.Host = host
	u.Scheme = "https"
	u.Path = attestationEndpoint

	resp, err := http.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var doc Document
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}
