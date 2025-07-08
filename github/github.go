package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/tinfoilsh/verifier/util"
)

// FetchDigest fetches the attestation digest for a given repo and tag
func FetchDigest(repo, tag string) (string, error) {
	url := fmt.Sprintf(`https://api-github-proxy.tinfoil.sh/%s/releases/download/%s/tinfoil.hash`, repo, tag)
	digestResp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	if digestResp.StatusCode != 200 {
		return "", fmt.Errorf("failed to fetch attestation digest: %s", digestResp.Status)
	}
	digest, err := io.ReadAll(digestResp.Body)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(digest)), nil
}

// FetchLatestDigest gets the latest release, tag, and attestation digest of a repo
func FetchLatestDigest(repo string) (string, error) {
	url := "https://api-github-proxy.tinfoil.sh/repos/" + repo + "/releases/latest"
	releaseResponse, err := util.Get(url)
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

	// Backwards compatibility for old EIF releases
	eifRegex := regexp.MustCompile(`EIF hash: ([a-fA-F0-9]{64})`)
	matches := eifRegex.FindStringSubmatch(responseJSON.Body)
	if len(matches) > 1 {
		return matches[1], nil
	}

	digest, err := FetchDigest(repo, responseJSON.TagName)
	if err != nil {
		return "", fmt.Errorf("failed to fetch digest for %s@%s: %v", repo, responseJSON.TagName, err)
	}
	return digest, nil
}

// FetchAttestationBundle fetches the sigstore bundle from a repo for a given repo and EIF hash
func FetchAttestationBundle(repo, digest string) ([]byte, error) {
	url := "https://gh-attestation-proxy.tinfoil.sh/repos/" + repo + "/attestations/sha256:" + digest
	bundleResponse, err := util.Get(url)
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
