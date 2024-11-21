package main

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/tinfoilanalytics/verifier/pkg/models"
	"github.com/tinfoilanalytics/verifier/pkg/nitro"
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

	var sigstoreMeasurements *models.Measurements
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

		sigstoreMeasurements, err = sigstore.VerifyAttestedMeasurements(
			sigstoreRootBytes,
			bundleBytes,
			*digest,
			*repo,
		)
		if err != nil {
			panic(err)
		}
		log.Println("Sigstore", sigstoreMeasurements)
	}

	var nitroMeasurements *models.Measurements
	if *attestationDoc != "" {
		var attDocBytes []byte
		var err error
		if strings.HasPrefix(*attestationDoc, "http") {
			log.Printf("Fetching attestation doc from %s", *attestationDoc)
			resp, err := http.Get(*attestationDoc)
			if err != nil {
				panic(err)
			}

			var attDocB64 string
			if err := json.NewDecoder(resp.Body).Decode(&attDocB64); err != nil {
				panic(err)
			}
			attDocBytes, err = base64.StdEncoding.DecodeString(attDocB64)
			if err != nil {
				panic(err)
			}
		} else {
			log.Printf("Reading attestation doc from %s", *attestationDoc)
			attDocBytes, err = os.ReadFile(*attestationDoc)
			if err != nil {
				panic(err)
			}
		}

		nitroMeasurements, err = nitro.VerifyAttestation(attDocBytes)
		if err != nil {
			panic(err)
		}
		log.Println("Nitro", nitroMeasurements)
	}

	if sigstoreMeasurements != nil && nitroMeasurements != nil {
		if sigstoreMeasurements.Equals(nitroMeasurements) {
			log.Println("PCR values match! Verification success")
		} else {
			log.Println("PCR register mismatch. Verification failed")
		}
	}
}
