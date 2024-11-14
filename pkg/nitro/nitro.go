package nitro

import (
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"github.com/tinfoilanalytics/verifier/pkg/models"
)

// wget https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip

//go:embed aws-nitro-root-g1.pem
var awsRootCertBytes []byte

var rootCert *x509.Certificate

func init() {
	// Parse AWS root cert
	b, _ := pem.Decode(awsRootCertBytes)
	if b == nil {
		panic("parsing root cert")
	}

	var err error
	rootCert, err = x509.ParseCertificate(b.Bytes)
	if err != nil {
		panic("parsing root cert: " + err.Error())
	}
}

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
