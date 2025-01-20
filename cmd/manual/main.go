package main

import (
	"bytes"
	_ "embed"
	"flag"
	"log"

	"github.com/tinfoilanalytics/verifier/pkg/attestation"
	"github.com/tinfoilanalytics/verifier/pkg/github"
	"github.com/tinfoilanalytics/verifier/pkg/sigstore"
)

var (
	enclaveHost = flag.String("e", "inference-enclave.tinfoil.sh", "Enclave hostname")
	repo        = flag.String("r", "tinfoilanalytics/nitro-enclave-build-demo", "Source repo (e.g. tinfoilanalytics/nitro-private-inference-image)")
)

func main() {
	flag.Parse()

	if *repo == "" || *enclaveHost == "" {
		log.Fatal("Missing required arguments")
	}

	var codeMeasurements, enclaveMeasurements *attestation.Measurement

	log.Printf("Fetching latest release for %s", *repo)
	latestTag, eifHash, err := github.FetchLatestRelease(*repo)
	if err != nil {
		log.Fatalf("Failed to fetch latest release: %v", err)
	}

	log.Printf("Fetching sigstore bundle from %s for latest version %s EIF %s", latestTag, *repo, eifHash)
	bundleBytes, err := github.FetchAttestationBundle(*repo, eifHash)
	if err != nil {
		log.Fatal(err)
	}

	sigstoreRootBytes, err := sigstore.FetchTrustRoot()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Verifying code measurements")
	codeMeasurements, err = sigstore.VerifyMeasurementAttestation(
		sigstoreRootBytes,
		bundleBytes,
		eifHash,
		*repo,
	)
	if err != nil {
		log.Fatalf("Failed to verify source measurements: %v", err)
	}

	if *enclaveHost != "" {
		log.Printf("Fetching attestation doc from %s", *enclaveHost)
		remoteAttestation, enclaveCertFP, err := attestation.Fetch(*enclaveHost)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Enclave TLS public key fingerprint: %x", enclaveCertFP)

		log.Println("Verifying enclave measurements")
		var attestedCertFP []byte
		enclaveMeasurements, attestedCertFP, err = remoteAttestation.Verify()
		if err != nil {
			log.Fatalf("Failed to parse enclave attestation doc: %v", err)
		}

		log.Printf("TLS certificate fingerprint: %x", attestedCertFP)

		if !bytes.Equal(enclaveCertFP, attestedCertFP) {
			log.Fatalf("Certificate fingerprint mismatch")
		} else {
			log.Println("Certificate fingerprint match")
		}
	}

	if codeMeasurements != nil && enclaveMeasurements != nil {
		if err := codeMeasurements.Equals(enclaveMeasurements); err != nil {
			log.Printf("PCR register mismatch. Verification failed: %v", err)
			log.Printf("Code: %s", codeMeasurements.Fingerprint())
			log.Printf("Enclave: %s", enclaveMeasurements.Fingerprint())
		} else {
			log.Println("Verification successful, measurements match")
		}
	}
}
