package github

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitHubFetchDigest(t *testing.T) {
	repo := "tinfoilsh/confidential-llama3-3-70b"
	tag := "v0.0.1"

	digest, err := FetchDigest(repo, tag)
	assert.NoError(t, err, "Failed to fetch digest for %s@%s", repo, tag)
	assert.NotEmpty(t, digest)

	latestDigest, err := FetchLatestDigest(repo)
	assert.NoError(t, err, "Failed to fetch latest digest for %s", repo)
	assert.NotEmpty(t, latestDigest, "Expected non-empty latest digest")
}

func TestFetchAttestationBundle(t *testing.T) {
	repo := "tinfoilsh/confidential-llama3-3-70b"
	tag := "v0.0.1"

	digest, err := FetchDigest(repo, tag)
	assert.NoError(t, err)

	bundle, err := FetchAttestationBundle(repo, digest)
	assert.NoError(t, err, "Failed to fetch attestation bundle for %s with digest %s", repo, digest)
	assert.NotEmpty(t, bundle)
}
