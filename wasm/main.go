//go:build js && wasm
// +build js,wasm

package main

import (
	_ "embed"
	"fmt"
	"syscall/js"

	"github.com/tinfoilanalytics/verifier/pkg/nitro"
	"github.com/tinfoilanalytics/verifier/pkg/sigstore"
)

// curl -o trusted_root.json https://tuf-repo-cdn.sigstore.dev/targets/4364d7724c04cc912ce2a6c45ed2610e8d8d1c4dc857fb500292738d4d9c8d2c.trusted_root.json
//
//go:embed trusted_root.json
var trustedRootBytes []byte

//go:embed bundle.jsonl
var bundleBytes []byte

//go:embed att_doc.bin
var attDocBytes []byte

func verify() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		digest := "8c168b97025c49a7f34c0da01b22200e4dc3b1f858e76fc4555967eb28722b11"

		sigstoreMeasurements, err := sigstore.VerifyAttestedMeasurements(
			trustedRootBytes,
			bundleBytes,
			digest,
		)
		if err != nil {
			panic(err)
		}
		fmt.Println("Sigstore", sigstoreMeasurements)

		nitroMeasurements, err := nitro.VerifyAttestation(attDocBytes)
		if err != nil {
			panic(err)
		}
		fmt.Println("Nitro", nitroMeasurements)

		fmt.Println("Match?", sigstoreMeasurements.Equals(nitroMeasurements))

		return "ok"
	})
}

func main() {
	js.Global().Set("verify", verify())
	<-make(chan struct{})
}
