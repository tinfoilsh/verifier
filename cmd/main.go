package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/tinfoilanalytics/verifier/pkg/attestation"
	"github.com/tinfoilanalytics/verifier/pkg/sigstore"
)

var (
	attestationDoc = flag.String("attestation", "", "Path to the attestation document or URL")
	digest         = flag.String("digest", "", "Artifact digest")
	repo           = flag.String("repo", "", "Attested repo (e.g. tinfoilanalytics/nitro-private-inference-image)")
)

func gitHubAttestation(digest string) ([]byte, error) {
	url := "https://api.github.com/repos/" + *repo + "/attestations/sha256:" + digest
	log.Printf("Fetching sigstore bundle from %s", url)
	bundleResponse, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	if bundleResponse.StatusCode != 200 {
		return nil, fmt.Errorf("failed to fetch sigstore bundle: %s", bundleResponse.Status)
	}

	var responseJSON struct {
		Attestations []struct {
			Bundle json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.NewDecoder(bundleResponse.Body).Decode(&responseJSON); err != nil {
		return nil, err
	}

	return responseJSON.Attestations[0].Bundle, nil
}

func main() {
	flag.Parse()

	var codeMeasurements, enclaveMeasurements *attestation.Measurement

	if *digest != "" {
		if *repo == "" {
			log.Fatal("Missing repo")
		}

		bundleBytes, err := gitHubAttestation(*digest)
		if err != nil {
			panic(err)
		}

		sigstoreResponse, err := http.Get("https://tuf-repo-cdn.sigstore.dev/targets/4364d7724c04cc912ce2a6c45ed2610e8d8d1c4dc857fb500292738d4d9c8d2c.trusted_root.json")
		if err != nil {
			panic(err)
		}
		sigstoreRootBytes, err := io.ReadAll(sigstoreResponse.Body)
		if err != nil {
			panic(err)
		}

		codeMeasurements, err = sigstore.VerifyAttestedMeasurements(
			sigstoreRootBytes,
			bundleBytes,
			*digest,
			*repo,
		)
		if err != nil {
			panic(err)
		}
		log.Println("Sigstore", codeMeasurements)
	}

	if *attestationDoc != "" {
		var attDocJSON []byte
		var err error
		if strings.HasPrefix(*attestationDoc, "http") {
			log.Printf("Fetching attestation doc from %s", *attestationDoc)
			resp, err := http.Get(*attestationDoc)
			if err != nil {
				panic(err)
			}
			defer resp.Body.Close()
			attDocJSON, err = io.ReadAll(resp.Body)
		} else {
			log.Printf("Reading attestation doc from %s", *attestationDoc)
			attDocJSON, err = os.ReadFile(*attestationDoc)
		}
		if err != nil {
			panic(err)
		}

		enclaveMeasurements, err = attestation.VerifyAttestationJSON(attDocJSON)
		if err != nil {
			log.Fatalf("Failed to parse enclave attestation doc: %v", err)
		}
	}

	if codeMeasurements != nil && enclaveMeasurements != nil {
		if err := codeMeasurements.Equals(enclaveMeasurements); err != nil {
			log.Println("PCR values match! Verification success")
		} else {
			log.Printf("PCR register mismatch. Verification failed: %v", err)
		}
	}
}
