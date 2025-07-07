//go:build js && wasm
// +build js,wasm

package util

import (
	"context"
	"fmt"

	fetch "marwan.io/wasm-fetch"
)

func Get(url string) ([]byte, map[string][]string, error) {
	resp, err := fetch.Fetch(url, &fetch.Opts{
		Method: fetch.MethodGet,
		Signal: context.Background(),
	})
	if err != nil {
		return nil, nil, err
	}
	if resp.Status > 299 {
		return nil, nil, fmt.Errorf("HTTP GET %s: %d %s", url, resp.Status, resp.StatusText)
	}
	return resp.Body, resp.Headers, nil
}
