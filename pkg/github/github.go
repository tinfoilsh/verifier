package github

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
)

// FetchLatestRelease gets the latest release and EIF hash of a repo
func FetchLatestRelease(repo string) (string, string, error) {
	url := "https://api.github.com/repos/" + repo + "/releases/latest"
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

// FetchAttestationBundle fetches the sigstore bundle from a repo for a given repo and EIF hash
func FetchAttestationBundle(repo, digest string) ([]byte, error) {
	url := "https://api.github.com/repos/" + repo + "/attestations/sha256:" + digest
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
