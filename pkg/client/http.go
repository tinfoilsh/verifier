package client

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
)

var (
	ErrNoTLS        = errors.New("no TLS connection")
	ErrCertMismatch = errors.New("certificate fingerprint mismatch")
)

type TLSBoundRoundTripper struct {
	ExpectedCertFP []byte
}

var _ http.RoundTripper = &TLSBoundRoundTripper{}

func (t *TLSBoundRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		return nil, err
	}

	if resp.TLS == nil {
		return nil, ErrNoTLS
	}

	certFP := sha256.Sum256(resp.TLS.PeerCertificates[0].Raw)
	if subtle.ConstantTimeCompare(t.ExpectedCertFP, certFP[:]) != 1 {
		return nil, ErrCertMismatch
	}

	return resp, err
}
