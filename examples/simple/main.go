package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/tinfoilsh/verifier/attestation"
	"github.com/tinfoilsh/verifier/github"
	"github.com/tinfoilsh/verifier/sigstore"
)

var (
	repo            = flag.String("r", "tinfoilsh/confidential-model-router", "config repo")
	enclave         = flag.String("e", "router.inf7.tinfoil.sh", "enclave host")
	insecure        = flag.Bool("i", false, "TLS insecure skip verify")
	attestationFile = flag.String("a", "", "path to attestation document file")
)

func main() {
	flag.Parse()

	if *insecure {
		log.Println("Running in insecure mode")
		http.DefaultTransport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	log.Println("Fetching SigStore trust root")
	sigstoreClient, err := sigstore.NewClient()
	if err != nil {
		log.Fatalf("failed to fetch trust root: %v", err)
	}

	var codeMeasurements *attestation.Measurement
	if *repo != "" {
		log.WithFields(log.Fields{
			"repo": *repo,
		}).Printf("Fetching latest release")
		digest, err := github.FetchLatestDigest(*repo)
		if err != nil {
			log.Fatalf("failed to fetch latest release: %v", err)
		}

		log.WithFields(log.Fields{
			"repo":   *repo,
			"digest": digest,
		}).Printf("Fetching runtime attestation")
		sigstoreBundle, err := github.FetchAttestationBundle(*repo, digest)
		if err != nil {
			log.Fatalf("failed to fetch attestation bundle: %v", err)
		}

		log.Printf("Verifying source attestation")
		codeMeasurements, err = sigstoreClient.VerifyAttestation(sigstoreBundle, digest, *repo)
		if err != nil {
			log.Fatalf("failed to verify attested measurements: %v", err)
		}
	}

	var enclaveAttestation *attestation.Document
	if *attestationFile != "" {
		log.Printf("Reading enclave attestation from %s", *attestationFile)
		enclaveAttestation, err = attestation.FromFile(*attestationFile)
		if err != nil {
			log.Fatalf("failed to read enclave attestation: %v", err)
		}
	} else {
		log.Printf("Fetching runtime attestation from %s", *enclave)
		enclaveAttestation, err = attestation.Fetch(*enclave)
		if err != nil {
			log.Fatalf("failed to fetch enclave measurements: %v", err)
		}
	}

	log.Printf("Fetching TLS public key from %s", *enclave)
	tlsPublicKey, err := attestation.TLSPublicKey(*enclave)
	if err != nil {
		log.Fatalf("failed to fetch TLS public key: %v", err)
	}
	log.Printf("Connection TLS public key: %s", tlsPublicKey)

	log.Println("Verifying enclave measurements")
	verification, err := enclaveAttestation.Verify()
	if err != nil {
		log.Fatalf("failed to verify enclave measurements: %v", err)
	}

	log.WithFields(log.Fields{
		"enclave": verification.Measurement,
		"runtime": codeMeasurements,
	}).Info("Measurements")

	if enclaveAttestation.Format == attestation.TdxGuestV1 || enclaveAttestation.Format == attestation.TdxGuestV2 {
		log.Println("Fetching latest hardware measurements")
		hwMeasurements, err := sigstoreClient.LatestHardwareMeasurements()
		if err != nil {
			log.Fatalf("failed to fetch hardware measurements: %v", err)
		}

		log.Println("Verifying hardware measurements")
		hwMeasurement, err := attestation.VerifyHardware(hwMeasurements, verification.Measurement)
		if err != nil {
			log.Fatalf("failed to verify hardware measurements: %v", err)
		}
		log.Printf("Matched hardware measurement: %s", hwMeasurement.ID)
	}

	log.WithFields(log.Fields{
		"tls_public_key_fp":  verification.TLSPublicKeyFP,
		"hpke_public_key_fp": verification.HPKEPublicKey,
	}).Println("Verified remote attestation")

	if verification.TLSPublicKeyFP != tlsPublicKey {
		log.Fatalf("TLS public key fingerprint mismatch: expected %s, got %s", tlsPublicKey, verification.TLSPublicKeyFP)
	} else {
		log.Println("TLS public key fingerprint matches")
	}

	if codeMeasurements != nil {
		out, err := codeMeasurements.EqualsDisplay(verification.Measurement)
		fmt.Println(out)
		if err != nil {
			log.Fatalf("Measurements do not match: %v", err)
		} else {
			log.Println("Measurements match")
		}
	} else {
		log.Println("No code measurements provided, skipping comparison")
	}
}
