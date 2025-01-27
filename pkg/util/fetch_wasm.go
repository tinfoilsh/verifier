//go:build js && wasm
// +build js,wasm

package util

import (
	"context"

	fetch "marwan.io/wasm-fetch"
)

func get(url string) ([]byte, error) {
	resp, err := fetch.Fetch(url, &fetch.Opts{
		Method: fetch.MethodGet,
		Signal: context.Background(),
	})
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}
