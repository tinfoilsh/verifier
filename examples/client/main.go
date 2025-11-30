package main

import (
	"log"

	"github.com/tinfoilsh/verifier/client"
)

func main() {
	// Create a client for a specific enclave and code repository
	// tinfoilClient := client.NewSecureClient("deepseek-r1-0528.inf9.tinfoil.sh", "tinfoilsh/confidential-deepseek-r1-0528")
	// tinfoilClient := client.NewSecureClient("deepseek-v31-terminus.inf7.tinfoil.sh", "tinfoilsh/confidential-deepseek-v31-terminus")
	tinfoilClient := client.NewSecureClient("llama-qwen.inf8.tinfoil.sh", "tinfoilsh/confidential-llama-qwen")
	// tinfoilClient := client.NewSecureClient("gpt-oss-120b.inf5.tinfoil.sh", "tinfoilsh/confidential-gpt-oss-120b")

	// Make HTTP requests - verification happens automatically
	resp, err := tinfoilClient.Get("/.well-known/tinfoil-attestation", nil)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	log.Printf("Response body: %s", resp.Body)

	// POST with headers and body
	headers := map[string]string{"Content-Type": "application/json"}
	body := []byte(`{"key": "value"}`)
	resp, err = tinfoilClient.Post("/api/submit", headers, body)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	log.Printf("Response body: %s", resp.Body)
}
