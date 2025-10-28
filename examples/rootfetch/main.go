package main

import (
	"log"
	"os"

	"github.com/tinfoilsh/verifier/sigstore"
)

func main() {
	trustedRootJSON, err := sigstore.FetchTrustRoot()
	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile("trusted_root.json", trustedRootJSON, 0644); err != nil {
		log.Fatal(err)
	}
}
