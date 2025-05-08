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
	"strings"
)

const (
	AWSNitroEnclaveV1 = "https://tinfoil.sh/predicate/aws-nitro-enclave/v1"
	SevGuestV1        = "https://tinfoil.sh/predicate/sev-snp-guest/v1"

	attestationEndpoint = "/.well-known/tinfoil-attestation"
)

var (
	ErrFormatMismatch      = errors.New("attestation format mismatch")
	ErrMeasurementMismatch = errors.New("measurement mismatch")
)

type Measurement struct {
	Type      string
	registers []string
}

type Verification struct {
	Measurement *Measurement
	PublicKeyFP string
}

// NewNitroMeasurement creates a measurement for an AWS Nitro Enclave.
// Nitro always has 3 PCR-style registers, so we validate the length.
func NewNitroMeasurement(pcr0, pcr1, pcr2 string) *Measurement {
	return &Measurement{
		Type:      AWSNitroEnclaveV1,
		registers: []string{pcr0, pcr1, pcr2},
	}
}

// NewSevMeasurement creates a measurement for an AMD SEV-SNP guest.
// SEV launch measurements have exactly one register.
func NewSevMeasurement(launch string) *Measurement {
	return &Measurement{
		Type:      SevGuestV1,
		registers: []string{launch},
	}
}

// Fingerprint computes the SHA-256 hash of all measurements, or returns the single measurement if there is only one
func (m *Measurement) Fingerprint() string {
	if len(m.registers) == 1 {
		return m.registers[0]
	}

	all := string(m.Type) + strings.Join(m.registers, "")
	return fmt.Sprintf("%x", sha256.Sum256([]byte(all)))
}

func (m *Measurement) Compare(other *Measurement) error {
	if m.Type != other.Type {
		return ErrFormatMismatch
	}
	if len(m.registers) != len(other.registers) {
		return ErrMeasurementMismatch
	}
	for i := 0; i < m.RegisterCount(); i++ {
		if m.GetRegister(i) != other.GetRegister(i) {
			return ErrMeasurementMismatch
		}
	}

	return nil
}

func (m *Measurement) RegisterCount() int { return len(m.registers) }

func (m *Measurement) GetRegister(i int) string {
	if i < 0 || i >= len(m.registers) {
		return ""
	}
	return m.registers[i]
}

func (m *Measurement) SetRegister(i int, r string) error {
	if i < 0 || i >= len(m.registers) {
		return fmt.Errorf("invalid register index: %d", i)
	}
	m.registers[i] = r
	return nil
}

// Document represents an attestation document
type Document struct {
	Format string `json:"format"`
	Body   string `json:"body"`
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
	if c.PeerCertificates == nil || len(c.PeerCertificates) == 0 {
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
