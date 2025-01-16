package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"

	"github.com/tinfoilanalytics/verifier/pkg/attestation"
	"github.com/tinfoilanalytics/verifier/pkg/sigstore"
)

var (
	attestationDoc = flag.String("u", "", "Attestation document URL")
	repo           = flag.String("r", "", "Attested repo (e.g. tinfoilanalytics/nitro-private-inference-image)")
)

func fetchLatestRelease(repo string) (string, string, error) {
	url := "https://api.github.com/repos/" + repo + "/releases/latest"
	log.Printf("Fetching latest release for %s", repo)
	releaseResponse, err := http.Get(url)
	if err != nil {
		return "", "", err
	}
	if releaseResponse.StatusCode != 200 {
		return "", "", fmt.Errorf("failed to fetch latest release: %s", releaseResponse.Status)
	}

	var responseJSON struct {
		TagName string `json:"tag_name"`
		Body    string `json:"body"`
	}
	if err := json.NewDecoder(releaseResponse.Body).Decode(&responseJSON); err != nil {
		return "", "", err
	}

	eifRegex := regexp.MustCompile(`EIF hash: ([a-fA-F0-9]{64})`)
	eifHash := eifRegex.FindStringSubmatch(responseJSON.Body)[1]

	return responseJSON.TagName, eifHash, nil
}

func gitHubAttestation(digest string) ([]byte, error) {
	url := "https://api.github.com/repos/" + *repo + "/attestations/sha256:" + digest
	log.Printf("Fetching sigstore bundle from %s for EIF %s", *repo, digest)
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

	latestTag, eifHash, err := fetchLatestRelease(*repo)
	if err != nil {
		log.Fatalf("Failed to fetch latest release: %v", err)
	}

	log.Printf("Latest release: %s", latestTag)
	log.Printf("EIF hash: %s", eifHash)

	if *repo == "" {
		log.Fatal("Missing repo")
	}

	bundleBytes, err := gitHubAttestation(eifHash)
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

	log.Println("Verifying code measurements")
	codeMeasurements, err = sigstore.VerifyAttestedMeasurements(
		sigstoreRootBytes,
		bundleBytes,
		eifHash,
		*repo,
	)
	if err != nil {
		log.Fatalf("Failed to verify source measurements: %v", err)
	}

	if *attestationDoc != "" {
		var attDocJSON []byte
		var err error
		log.Printf("Fetching attestation doc from %s", *attestationDoc)
		resp, err := http.Get(*attestationDoc)
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()

		attDocJSON, err = io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}

		log.Println("Verifying enclave measurements")
		var tlsPubkey []byte
		enclaveMeasurements, tlsPubkey, err = attestation.VerifyAttestationJSON(attDocJSON)
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
