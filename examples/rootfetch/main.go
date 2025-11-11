package main

import (
	"flag"
	"log"
	"os"

	"github.com/tinfoilsh/verifier/sigstore"
)

var (
	outputFile = flag.String("o", "trusted_root.json", "output file")
)

func main() {
	flag.Parse()

	log.Print("Fetching latest SigStore trust root")

	trustedRootJSON, err := sigstore.FetchTrustRoot()
	if err != nil {
		log.Fatal(err)
	}

	if err := os.WriteFile(*outputFile, trustedRootJSON, 0644); err != nil {
		log.Fatal(err)
	}
}
