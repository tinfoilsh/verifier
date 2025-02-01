package util

import (
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

type Fetcher struct{}

func (_ *Fetcher) DownloadFile(urlPath string, maxLength int64, timeout time.Duration) ([]byte, error) {
	return Get(urlPath)
}

var (
	_ fetcher.Fetcher = &Fetcher{}
)

func NewFetcher() *Fetcher {
	return &Fetcher{}
}
