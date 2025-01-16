//go:build js && wasm
// +build js,wasm

package main

import (
	_ "embed"
	"syscall/js"

	"github.com/tinfoilanalytics/verifier/pkg/attestation"
	"github.com/tinfoilanalytics/verifier/pkg/sigstore"
)

// curl -o trusted_root.json https://tuf-repo-cdn.sigstore.dev/targets/4364d7724c04cc912ce2a6c45ed2610e8d8d1c4dc857fb500292738d4d9c8d2c.trusted_root.json
//
//go:embed trusted_root.json
var trustedRootBytes []byte

func verifyCode() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		digest := args[0].String()
		bundleBytes := []byte(args[1].String())
		repo := args[2].String()

		measurement, err := sigstore.VerifyMeasurementAttestation(
			trustedRootBytes,
			bundleBytes,
			digest,
			repo,
		)
		if err != nil {
			panic(err)
		}

		return measurement.Fingerprint()
	})
}

func verifyEnclave() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		measurement, _, err := attestation.VerifyAttestationJSON([]byte(args[0].String()))
		if err != nil {
			panic(err)
		}
		return measurement.Fingerprint()
	})
}

func main() {
	js.Global().Set("verifySigstore", verifyCode())
	js.Global().Set("verifyNitro", verifyEnclave())
	<-make(chan struct{})
}
