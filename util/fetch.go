package util

import (
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

type Fetcher struct{}

func (_ *Fetcher) DownloadFile(urlPath string, maxLength int64, timeout time.Duration) ([]byte, error) {
	body, _, err := Get(urlPath)
	if err != nil {
		return nil, err
	}
	return body, nil
}

var (
	_ fetcher.Fetcher = &Fetcher{}
)

func NewFetcher() *Fetcher {
	return &Fetcher{}
}
