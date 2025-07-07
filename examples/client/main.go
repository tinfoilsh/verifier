package main

import (
	"log"

	"github.com/tinfoilsh/verifier/client"
)

func main() {
	// Create a client for a specific enclave and code repository
	tinfoilClient := client.NewSecureClient("tinfoil-enclave.example.com", "exampleorg/repo")

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
