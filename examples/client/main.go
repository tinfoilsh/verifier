package main

//go:generate go run ../../rootfetch/main.go -o ../../client/trusted_root.json

import (
	"log"

	"github.com/tinfoilsh/verifier/client"
)

func main() {
	tinfoilClient, err := client.NewDefaultClient()
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	log.Printf("Connected to enclave: %s", tinfoilClient.Enclave())

	body := []byte(`{"model":"gpt-oss-120b-free","messages":[{"role":"user","content":"What is 2+2?"}]}`)

	headers := map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer tinfoil",
	}

	resp, err := tinfoilClient.Post("/v1/chat/completions", headers, body)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}

	log.Printf("Response: %s", string(resp.Body))
}
