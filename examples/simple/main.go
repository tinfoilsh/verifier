package main

import (
	"flag"
	"log"

	"github.com/tinfoilsh/verifier/attestation"
	"github.com/tinfoilsh/verifier/github"
	"github.com/tinfoilsh/verifier/sigstore"
)

var (
	repo            = flag.String("r", "tinfoilsh/confidential-llama-mistral-qwen-turbo", "")
	enclave         = flag.String("e", "large.inf4.tinfoil.sh", "")
	attestationFile = flag.String("a", "", "")
)

func main() {
	flag.Parse()

	log.Printf("Fetching latest release for %s", *repo)
	digest, err := github.FetchLatestDigest(*repo)
	if err != nil {
		log.Fatalf("failed to fetch latest release: %v", err)
	}

	log.Printf("Fetching attestation bundle for %s@%s", *repo, digest)
	sigstoreBundle, err := github.FetchAttestationBundle(*repo, digest)
	if err != nil {
		log.Fatalf("failed to fetch attestation bundle: %v", err)
	}

	log.Println("Fetching SigStore trust root")
	sigstoreClient, err := sigstore.NewClient()
	if err != nil {
		log.Fatalf("failed to fetch trust root: %v", err)
	}

	log.Printf("Verifying attested measurements for %s@%s", *repo, digest)
	codeMeasurements, err := sigstoreClient.VerifyAttestation(sigstoreBundle, digest, *repo)
	if err != nil {
		log.Fatalf("failed to verify attested measurements: %v", err)
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

	log.Println("Verifying enclave measurements")
	verification, err := enclaveAttestation.Verify()
	if err != nil {
		log.Fatalf("failed to verify enclave measurements: %v", err)
	}

	if enclaveAttestation.Format == attestation.TdxGuestV1 {
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

	log.Println("Comparing measurements")
	if err := codeMeasurements.Equals(verification.Measurement); err != nil {
		log.Fatalf("Measurements do not match: %v", err)
	}

	log.Println("Verification successful!")
	log.Printf("Public key fingerprint: %s", verification.PublicKeyFP)
	log.Printf("Code Measurement: %+v", codeMeasurements)
	log.Printf("Enclave Measurement: %+v", verification.Measurement)
}
