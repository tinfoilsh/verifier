//go:build js && wasm
// +build js,wasm

package util

import (
	"context"
	"net"
	"time"
)

func init() {
	r := &net.Resolver{
		PreferGo: false,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * 5,
			}
			return d.DialContext(ctx, network, "9.9.9.9:53")
		},
	}
	net.DefaultResolver = r
}
