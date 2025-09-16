package attestation

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
)

type PredicateType string

const (
	// CC guest v1 types include only the TLS key fingerprint in the body
	SevGuestV1 PredicateType = "https://tinfoil.sh/predicate/sev-snp-guest/v1"
	TdxGuestV1 PredicateType = "https://tinfoil.sh/predicate/tdx-guest/v1"

	// CC guest v2 types include a JSON strucutre containing the TLS key fingerprint and optionally HPKE public key
	SevGuestV2 PredicateType = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
	TdxGuestV2 PredicateType = "https://tinfoil.sh/predicate/tdx-guest/v2"

	SnpTdxMultiPlatformV1  PredicateType = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
	HardwareMeasurementsV1 PredicateType = "https://tinfoil.sh/predicate/hardware-measurements/v1"

	attestationEndpoint = "/.well-known/tinfoil-attestation"
)

var (
	ErrFormatMismatch              = errors.New("attestation format mismatch")
	ErrMeasurementMismatch         = errors.New("measurement mismatch")
	ErrRtmr1Mismatch               = errors.New("RTMR1 mismatch")
	ErrRtmr2Mismatch               = errors.New("RTMR2 mismatch")
	ErrFewRegisters                = errors.New("fewer registers than expected")
	ErrMultiPlatformMismatch       = errors.New("multi-platform measurement mismatch")
	ErrMultiPlatformSevSnpMismatch = errors.New("multi-platform SEV-SNP measurement mismatch")
)

type Measurement struct {
	Type      PredicateType `json:"type"`
	Registers []string      `json:"registers"`
}

type Verification struct {
	Measurement *Measurement `json:"measurement"`
	PublicKeyFP string       `json:"public_key"`
}

func (m *Measurement) Equals(other *Measurement) error {
	// Base case: if both measurements are multi-platform, compare directly
	if m.Type == SnpTdxMultiPlatformV1 && other.Type == SnpTdxMultiPlatformV1 {
		if !slices.Equal(m.Registers, other.Registers) {
			return ErrMultiPlatformMismatch
		}
		return nil
	}

	// Flip comparison order for multi-platform measurements
	if other.Type == SnpTdxMultiPlatformV1 {
		return other.Equals(m)
	}

	if m.Type == SnpTdxMultiPlatformV1 {
		switch other.Type {
		case TdxGuestV1:
			if len(m.Registers) < 3 || len(other.Registers) < 4 {
				return ErrFewRegisters
			}

			expectedRtmr1 := m.Registers[1] // 0 is SNP
			expectedRtmr2 := m.Registers[2]

			actualRtmr1 := other.Registers[2] // 0 is MRTD, 1 is RTMR0
			actualRtmr2 := other.Registers[3]

			if expectedRtmr1 != actualRtmr1 {
				return ErrRtmr1Mismatch
			}
			if expectedRtmr2 != actualRtmr2 {
				return ErrRtmr2Mismatch
			}
			return nil
		case SevGuestV1:
			expectedSevSnp := m.Registers[0]
			actualSevSnp := other.Registers[0]

			if expectedSevSnp != actualSevSnp {
				return ErrMultiPlatformSevSnpMismatch
			}
			return nil
		default:
			return fmt.Errorf("unsupported enclave platform for multi-platform code measurements: %s", other.Type)
		}
	}

	if m.Type != other.Type {
		return ErrFormatMismatch
	}

	if !slices.Equal(m.Registers, other.Registers) {
		return ErrMeasurementMismatch
	}

	return nil
}

// Document represents an attestation document
type Document struct {
	Format PredicateType `json:"format"`
	Body   string        `json:"body"`
}

// NewDocument creates a new attestation document from a given format and body
func NewDocument(format PredicateType, body []byte) (*Document, error) {
	// Compress attestation body
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(body); err != nil {
		return nil, fmt.Errorf("failed to write data: %v", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("closing reader: %v", err)
	}

	return &Document{
		Format: format,
		Body:   base64.StdEncoding.EncodeToString(b.Bytes()),
	}, nil
}

// Hash returns the SHA-256 hash of the attestation document
func (d *Document) Hash() string {
	all := string(d.Format) + d.Body
	return fmt.Sprintf("%x", sha256.Sum256([]byte(all)))
}

// Verify checks the attestation document against its trust root and returns the inner measurements
func (d *Document) Verify() (*Verification, error) {
	switch d.Format {
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

// FromFile reads an attestation document from a file
func FromFile(path string) (*Document, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var doc Document
	if err := json.NewDecoder(f).Decode(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}
