package main

import (
	"flag"
	"log"

	"github.com/tinfoilsh/verifier/attestation"
	"github.com/tinfoilsh/verifier/github"
	"github.com/tinfoilsh/verifier/sigstore"
)

var (
	repo    = flag.String("r", "tinfoilsh/confidential-llama3-3-70b", "")
	enclave = flag.String("e", "llama3-3-70b.model.tinfoil.sh", "")
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
	trustRootJSON, err := sigstore.FetchTrustRoot()
	if err != nil {
		log.Fatalf("failed to fetch trust root: %v", err)
	}

	log.Printf("Verifying attested measurements for %s@%s", *repo, digest)
	codeMeasurements, err := sigstore.VerifyAttestation(trustRootJSON, sigstoreBundle, digest, *repo)
	if err != nil {
		log.Fatalf("failed to verify attested measurements: %v", err)
	}

	log.Printf("Fetching runtime attestation from %s", *enclave)
	enclaveAttestation, err := attestation.Fetch(*enclave)
	if err != nil {
		log.Fatalf("failed to fetch enclave measurements: %v", err)
	}

	log.Println("Verifying enclave measurements")
	verification, err := enclaveAttestation.Verify()
	if err != nil {
		log.Fatalf("failed to verify enclave measurements: %v", err)
	}

	log.Println("Comparing measurements")
	if err := codeMeasurements.Equals(verification.Measurement); err != nil {
		log.Fatalf("code measurements do not match: %v", err)
	}

	log.Println("Verification successful!")
	log.Printf("Public key fingerprint: %s", verification.PublicKeyFP)
	log.Printf("Measurement: %s", codeMeasurements.Fingerprint())
}
