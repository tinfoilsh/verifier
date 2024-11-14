package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/tinfoilanalytics/verifier/pkg/nitro"
	"github.com/tinfoilanalytics/verifier/pkg/sigstore"
)

const repo = "tinfoilanalytics/nitro-enclave-pipeline-test"

func gitHubAttestation(digest string) ([]byte, error) {
	bundleResponse, err := http.Get("https://api.github.com/repos/" + repo + "/attestations/sha256:" + digest)
	if err != nil {
		return nil, err
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
	digest := "8c168b97025c49a7f34c0da01b22200e4dc3b1f858e76fc4555967eb28722b11"

	bundleBytes, err := gitHubAttestation(digest)
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

	sigstoreMeasurements, err := sigstore.VerifyAttestedMeasurements(
		sigstoreRootBytes,
		bundleBytes,
		digest,
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Sigstore", sigstoreMeasurements)

	attDocBytes, err := os.ReadFile("att_doc.bin")
	if err != nil {
		panic(err)
	}
	nitroMeasurements, err := nitro.VerifyAttestation(attDocBytes)
	if err != nil {
		panic(err)
	}
	fmt.Println("Nitro", nitroMeasurements)

	fmt.Println("Match?", sigstoreMeasurements.Equals(nitroMeasurements))
}
