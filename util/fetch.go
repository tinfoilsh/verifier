package util

import (
	"time"

	"github.com/google/go-sev-guest/verify/trust"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

type Fetcher struct{}

func (_ *Fetcher) Get(url string) ([]byte, error) {
	return get(url)
}

func (_ *Fetcher) DownloadFile(urlPath string, maxLength int64, timeout time.Duration) ([]byte, error) {
	return get(urlPath)
}

var (
	_ trust.HTTPSGetter = &Fetcher{}
	_ fetcher.Fetcher   = &Fetcher{}
)

func NewFetcher() *Fetcher {
	return &Fetcher{}
}
