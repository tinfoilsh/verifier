package main

import (
	"bytes"
	"io"
	"log"

	"github.com/tinfoilanalytics/verifier/pkg/client"
)

func main() {
	client := client.NewSecureClient(
		"inference-enclave.tinfoil.sh",
		"tinfoilanalytics/nitro-enclave-build-demo",
	)
	if err := client.Verify(); err != nil {
		log.Fatal(err)
	}

	vs := client.VerificationState()
	log.Printf("Cert fingerprint: %x\n", vs.CertFingerprint)
	log.Printf("EIF hash: %s\n", vs.EIFHash)

	resp, err := client.HTTPClient().Post("https://inference-enclave.tinfoil.sh/api/chat", "application/json", bytes.NewBufferString(`{
	"model": "llama3.2:1b",
	"stream": false,
	"messages": [
		{"role": "user","content": "What is 1+1?"}
	]
}`))
	if err != nil {
		log.Fatal(err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	log.Println(string(body))
}
