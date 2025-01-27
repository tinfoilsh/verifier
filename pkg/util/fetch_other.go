//go:build !wasm
// +build !wasm

package util

import (
	"io"
	"net/http"
)

func get(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(resp.Body)
}
