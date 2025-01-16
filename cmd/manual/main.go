package main

import (
	_ "embed"
	"flag"
	"io"
	"log"
	"net/http"

	"github.com/tinfoilanalytics/verifier/pkg/attestation"
	"github.com/tinfoilanalytics/verifier/pkg/github"
	"github.com/tinfoilanalytics/verifier/pkg/sigstore"
)

var (
	enclaveHost = flag.String("e", "", "Enclave hostname")
	repo        = flag.String("r", "", "Source repo (e.g. tinfoilanalytics/nitro-private-inference-image)")
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

	log.Printf("Latest release: %s", latestTag)
	log.Printf("EIF hash: %s", eifHash)

	log.Printf("Fetching sigstore bundle from %s for EIF %s", *repo, eifHash)
	bundleBytes, err := github.FetchAttestationBundle(*repo, eifHash)
	if err != nil {
		log.Fatal(err)
	}

	sigstoreResponse, err := http.Get("https://tuf-repo-cdn.sigstore.dev/targets/4364d7724c04cc912ce2a6c45ed2610e8d8d1c4dc857fb500292738d4d9c8d2c.trusted_root.json")
	if err != nil {
		log.Fatal(err)
	}
	sigstoreRootBytes, err := io.ReadAll(sigstoreResponse.Body)
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
		remoteAttestation, err := attestation.Fetch(*enclaveHost)
		if err != nil {
			log.Fatal(err)
		}

		log.Println("Verifying enclave measurements")
		var tlsPubkey []byte
		enclaveMeasurements, tlsPubkey, err = remoteAttestation.Verify()
		if err != nil {
			log.Fatalf("Failed to parse enclave attestation doc: %v", err)
		}

		log.Printf("TLS public key fingerprint: %x", tlsPubkey)
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
