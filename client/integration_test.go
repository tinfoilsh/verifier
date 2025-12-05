package client

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/*
Run only when TINFOIL_* environment variables are present.
The job that sets those vars lives in .github/workflows/integration.yml.
*/

const (
	enclaveEnvVar = "TINFOIL_ENCLAVE"
	repoEnvVar    = "TINFOIL_REPO"
	apiKeyEnvVar  = "TINFOIL_API_KEY"
)

func skipIfMissingEnvVars(t *testing.T) (enclave, repo, apiKey string) {
	enclave = os.Getenv(enclaveEnvVar)
	repo = os.Getenv(repoEnvVar)
	apiKey = os.Getenv(apiKeyEnvVar)

	if enclave == "" || repo == "" {
		t.Skipf("Missing Tinfoil integration settings: %s or %s not set", enclaveEnvVar, repoEnvVar)
	}

	if apiKey == "" {
		apiKey = "tinfoil" // Default API key
	}

	return enclave, repo, apiKey
}

// ChatCompletionRequest represents a chat completion request
type ChatCompletionRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

// Message represents a chat message
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatCompletionResponse represents a chat completion response
type ChatCompletionResponse struct {
	Choices []Choice `json:"choices"`
}

// Choice represents a choice in the chat completion response
type Choice struct {
	Message Message `json:"message"`
}

func TestBasicChatCompletion(t *testing.T) {
	enclave, repo, apiKey := skipIfMissingEnvVars(t)

	// Create secure client
	client := NewSecureClient(enclave, repo)

	// Prepare chat completion request
	request := ChatCompletionRequest{
		Model: "gpt-oss-120b-free",
		Messages: []Message{
			{
				Role:    "user",
				Content: "Hi",
			},
		},
	}

	requestBody, err := json.Marshal(request)
	require.NoError(t, err)

	// Make the request
	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer " + apiKey,
	}

	resp, err := client.Post("/v1/chat/completions", headers, requestBody)
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode, "Expected successful response, got: %s", string(resp.Body))

	// Parse response
	var chatResponse ChatCompletionResponse
	err = json.Unmarshal(resp.Body, &chatResponse)
	require.NoError(t, err)

	// Verify response contains non-empty content
	require.NotEmpty(t, chatResponse.Choices, "Response should contain at least one choice")
	assert.NotEmpty(t, chatResponse.Choices[0].Message.Content, "Response content should not be empty")

	// Log the response content (like the Python test does)
	t.Logf("Response content: %s", chatResponse.Choices[0].Message.Content)
}
