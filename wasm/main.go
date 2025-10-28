//go:build js && wasm
// +build js,wasm

package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"syscall/js"

	"github.com/tinfoilsh/verifier/attestation"
	"github.com/tinfoilsh/verifier/client"
	"github.com/tinfoilsh/verifier/sigstore"
	"github.com/tinfoilsh/verifier/util"
)

var version = "dev" // set by build process

//go:embed trusted_root.json
var trustedRootJSON []byte

func verifyCode() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) interface{} {
			resolve := promiseArgs[0]
			reject := promiseArgs[1]

			go func() {
				repo := args[0].String()
				digest := args[1].String()

				bundleURL := "https://gh-attestation-proxy.tinfoil.sh/repos/" + repo + "/attestations/sha256:" + digest
				log.Printf("Fetching bundle from %s...", bundleURL)
				bundle, _, err := util.Get(bundleURL)
				if err != nil {
					reject.Invoke(err.Error())
					return
				}

				var attestationsData struct {
					Attestations []struct {
						Bundle json.RawMessage `json:"bundle"`
					} `json:"attestations"`
				}
				if err := json.Unmarshal(bundle, &attestationsData); err != nil {
					reject.Invoke(err.Error())
					return
				}

				bundleJSON, err := attestationsData.Attestations[0].Bundle.MarshalJSON()
				if err != nil {
					reject.Invoke(err.Error())
					return
				}

				measurement, err := sigstore.VerifyAttestation(trustedRootJSON, bundleJSON, digest, repo)
				if err != nil {
					reject.Invoke(err.Error())
					return
				}
				measurementJSON, err := json.Marshal(measurement)
				if err != nil {
					reject.Invoke(err.Error())
					return
				}

				resolve.Invoke(js.ValueOf(string(measurementJSON)))
			}()

			return nil
		})

		return js.Global().Get("Promise").New(handler)
	})
}

func verifyEnclave() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) interface{} {
			resolve := promiseArgs[0]
			reject := promiseArgs[1]

			go func() {
				enclaveHostname := args[0].String()

				var u url.URL
				u.Scheme = "https"
				u.Host = enclaveHostname
				u.Path = "/.well-known/tinfoil-attestation"
				attestationURL := u.String()

				log.Printf("Fetching attestation from %s...", attestationURL)
				attDoc, _, err := util.Get(attestationURL)
				if err != nil {
					reject.Invoke(err.Error())
					return
				}

				log.Println("Verifying attestation...")
				verification, err := attestation.VerifyAttestationJSON(attDoc)
				if err != nil {
					errorMsg := fmt.Sprintf("Verification failed: %v", err)
					reject.Invoke(errorMsg)
					return
				}

				jsonMeasurement, err := json.Marshal(verification.Measurement)
				if err != nil {
					reject.Invoke(err.Error())
					return
				}

				result := map[string]interface{}{
					"tls_public_key":  verification.TLSPublicKeyFP,
					"hpke_public_key": verification.HPKEPublicKey,
					"certificate":     verification.TLSPublicKeyFP, // Fallback for backwards compatibility
					"measurement":     string(jsonMeasurement),
				}
				resolve.Invoke(js.ValueOf(result))
			}()

			return nil
		})

		return js.Global().Get("Promise").New(handler)
	})
}

func verify() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) interface{} {
			resolve := promiseArgs[0]
			reject := promiseArgs[1]

			go func() {
				enclaveHostname := args[0].String()
				repo := args[1].String()

				groundTruthJSON, err := client.VerifyJSON(trustedRootJSON, enclaveHostname, repo)
				if err != nil {
					reject.Invoke(err.Error())
					return
				}

				resolve.Invoke(js.ValueOf(groundTruthJSON))
			}()

			return nil
		})

		return js.Global().Get("Promise").New(handler)
	})
}

func main() {
	js.Global().Set("verifyEnclave", verifyEnclave())
	js.Global().Set("verifyCode", verifyCode())
	js.Global().Set("verify", verify())
	js.Global().Set("verifierVersion", version)
	<-make(chan struct{})
}
