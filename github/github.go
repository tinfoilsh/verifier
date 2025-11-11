package github

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tinfoilsh/verifier/util"
)

// FetchLatestTag fetches the latest tag for a repo
func FetchLatestTag(repo string) (string, error) {
	url := "https://api-github-proxy.tinfoil.sh/repos/" + repo + "/releases/latest"
	releaseResponse, _, err := util.Get(url)
	if err != nil {
		return "", err
	}

	var responseJSON struct {
		TagName string `json:"tag_name"`
		Body    string `json:"body"`
	}
	if err := json.Unmarshal(releaseResponse, &responseJSON); err != nil {
		return "", err
	}

	return responseJSON.TagName, nil
}

// FetchDigest fetches the attestation digest for a given repo and tag
func FetchDigest(repo, tag string) (string, error) {
	url := fmt.Sprintf(`https://api-github-proxy.tinfoil.sh/%s/releases/download/%s/tinfoil.hash`, repo, tag)
	digest, _, err := util.Get(url)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(digest)), nil
}

// FetchLatestDigest gets the latest release, tag, and attestation digest of a repo
func FetchLatestDigest(repo string) (string, error) {
	latestTag, err := FetchLatestTag(repo)
	if err != nil {
		return "", fmt.Errorf("failed to fetch latest tag: %v", err)
	}
	digest, err := FetchDigest(repo, latestTag)
	if err != nil {
		return "", fmt.Errorf("failed to fetch digest for %s@%s: %v", repo, latestTag, err)
	}
	return digest, nil
}

// FetchAttestationBundle fetches the sigstore bundle from a repo for a given repo and EIF hash
func FetchAttestationBundle(repo, digest string) ([]byte, error) {
	url := "https://gh-attestation-proxy.tinfoil.sh/repos/" + repo + "/attestations/sha256:" + digest
	bundleResponse, _, err := util.Get(url)
	if err != nil {
		return nil, err
	}

	var responseJSON struct {
		Attestations []struct {
			Bundle json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}

	if err := json.Unmarshal(bundleResponse, &responseJSON); err != nil {
		return nil, err
	}

	return responseJSON.Attestations[0].Bundle, nil
}
