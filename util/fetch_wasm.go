//go:build js && wasm
// +build js,wasm

package util

import (
	"fmt"
	"syscall/js"
)

func Get(url string) ([]byte, map[string][]string, error) {
	// Use native JavaScript fetch API to properly handle binary data
	promise := js.Global().Call("fetch", url)

	// Wait for the promise to resolve
	result, err := awaitPromise(promise)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch failed: %v", err)
	}

	// Check response status
	status := result.Get("status").Int()
	if status > 299 {
		statusText := result.Get("statusText").String()
		return nil, nil, fmt.Errorf("HTTP GET %s: %d %s", url, status, statusText)
	}

	// Get response as ArrayBuffer to preserve binary data
	arrayBufferPromise := result.Call("arrayBuffer")
	arrayBufferResult, err := awaitPromise(arrayBufferPromise)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get array buffer: %v", err)
	}

	// Convert ArrayBuffer to []byte
	uint8Array := js.Global().Get("Uint8Array").New(arrayBufferResult)
	length := uint8Array.Get("length").Int()
	data := make([]byte, length)
	js.CopyBytesToGo(data, uint8Array)

	// Extract headers
	headers := make(map[string][]string)
	headersObj := result.Get("headers")

	// Iterate through headers using forEach
	callback := js.FuncOf(func(this js.Value, args []js.Value) any {
		value := args[0].String()
		key := args[1].String()
		headers[key] = []string{value}
		return nil
	})
	defer callback.Release()

	headersObj.Call("forEach", callback)

	return data, headers, nil
}

// awaitPromise waits for a JavaScript Promise to resolve and returns the result
func awaitPromise(promise js.Value) (js.Value, error) {
	resultChan := make(chan js.Value, 1)
	errorChan := make(chan js.Value, 1)

	thenCallback := js.FuncOf(func(this js.Value, args []js.Value) any {
		resultChan <- args[0]
		return nil
	})
	defer thenCallback.Release()

	catchCallback := js.FuncOf(func(this js.Value, args []js.Value) any {
		errorChan <- args[0]
		return nil
	})
	defer catchCallback.Release()

	promise.Call("then", thenCallback).Call("catch", catchCallback)

	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errorChan:
		return js.Value{}, fmt.Errorf("promise rejected: %s", err.String())
	}
}
