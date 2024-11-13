package nitro

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/tinfoilanalytics/verifier/pkg/models"
)

// https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
const AwsRootCert = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`

// AttestationDocument represents an AWS Nitro Enclave attestation document in CBOR format
type AttestationDocument struct {
	ModuleID    string          `cbor:"module_id"`
	Timestamp   uint64          `cbor:"timestamp"`
	Digest      string          `cbor:"digest"`
	PCRs        map[uint][]byte `cbor:"pcrs"`
	Certificate []byte          `cbor:"certificate"`
	CABundle    [][]byte        `cbor:"cabundle"`
	PublicKey   []byte          `cbor:"public_key"`
	UserData    []byte          `cbor:"user_data"`
	Nonce       []byte          `cbor:"nonce"`
}

// VerifyAttestation verifies an AWS Nitro Enclave attestation document and returns the PCR measurements
func VerifyAttestation(attDocBytes []byte) (*models.Measurements, error) {
	// Decode attestation document from CBOR
	var msg cose.UntaggedSign1Message
	if err := msg.UnmarshalCBOR(attDocBytes); err != nil {
		return nil, fmt.Errorf("parsing signature: %w", err)
	}
	var attDoc AttestationDocument
	if err := cbor.Unmarshal(msg.Payload, &attDoc); err != nil {
		return nil, fmt.Errorf("parsing inner attestation document: %w", err)
	}

	// Parse inner certificate to extract pubkey
	cert, err := x509.ParseCertificate(attDoc.Certificate)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	// Verify COSE signature
	verifier, err := cose.NewVerifier(cose.AlgorithmES384, cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return nil, fmt.Errorf("verifying signature: %w", err)
	}

	// Parse AWS root cert
	b, _ := pem.Decode([]byte(AwsRootCert))
	if b == nil {
		return nil, fmt.Errorf("parsing root cert")
	}
	rootCert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing root cert: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	intermediates := x509.NewCertPool()
	for _, ca := range attDoc.CABundle {
		if caCert, err := x509.ParseCertificate(ca); err == nil {
			intermediates.AddCert(caCert)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}
	if _, err := cert.Verify(opts); err != nil {
		return nil, fmt.Errorf("verifying certificate: %w", err)
	}

	return &models.Measurements{
		PCR0: hex.EncodeToString(attDoc.PCRs[0]),
		PCR1: hex.EncodeToString(attDoc.PCRs[1]),
		PCR2: hex.EncodeToString(attDoc.PCRs[2]),
	}, nil
}
