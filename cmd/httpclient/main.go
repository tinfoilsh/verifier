package main

import (
	"log"

	"github.com/tinfoilanalytics/verifier/pkg/client"
)

func main() {
	client := client.NewSecureClient(
		"inference-enclave.tinfoil.sh",
		"tinfoilanalytics/nitro-enclave-build-demo",
	)

	vs, err := client.Verify()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Cert fingerprint: %x\n", vs.CertFingerprint)
	log.Printf("EIF hash: %s\n", vs.EIFHash)

	log.Println("Sending prompt to enclave...")
	resp, err := client.Post(
		"https://inference-enclave.tinfoil.sh/api/chat",
		map[string]string{"Content-Type": "application/json"},
		[]byte(`{
	"model": "llama3.2:1b",
	"stream": false,
	"messages": [
		{"role": "user","content": "What is 1+1?"}
	]
}`))
	if err != nil {
		log.Fatal(err)
	}

	log.Println(string(resp.Body))
}
