package client

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/http"
)

var (
	ErrNoTLS              = errors.New("no TLS connection")
	ErrCertMismatch       = errors.New("certificate fingerprint mismatch")
	ErrNoValidCertificate = errors.New("no valid certificate")
)

type TLSBoundRoundTripper struct {
	ExpectedCertFP []byte
}

var _ http.RoundTripper = &TLSBoundRoundTripper{}

func (t *TLSBoundRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if len(t.ExpectedCertFP) == 0 {
		return nil, ErrNoValidCertificate
	}

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		return nil, err
	}

	if resp.TLS == nil {
		return nil, ErrNoTLS
	}

	certFP := sha256.Sum256(resp.TLS.PeerCertificates[0].Raw)
	if !bytes.Equal(t.ExpectedCertFP, certFP[:]) {
		return nil, ErrCertMismatch
	}

	return resp, err
}
