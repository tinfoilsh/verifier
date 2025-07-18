//go:build !wasm
// +build !wasm

package util

import (
	"fmt"
	"io"
	"net/http"
)

func Get(url string) ([]byte, map[string][]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode > 299 {
		return nil, nil, fmt.Errorf("HTTP GET %s: %d %s", url, resp.StatusCode, resp.Status)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return body, resp.Header, nil
}
