//go:build !wasm
// +build !wasm

package util

import (
	"fmt"
	"io"
	"net/http"
)

func Get(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP GET %s: %d %s", url, resp.StatusCode, resp.Status)
	}
	return io.ReadAll(resp.Body)
}
