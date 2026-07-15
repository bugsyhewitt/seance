// Package httpclient provides a constructor for the HTTP client used by séance
// output sinks. Every sink that speaks HTTPS builds the same
// http.Transport+http.Client pattern; this helper centralises it so changes
// (e.g. connection pooling tuning, proxy support) land in one place.
package httpclient

import (
	"crypto/tls"
	"net/http"
	"time"
)

// New returns an *http.Client with the given per-request timeout and TLS
// verification setting. A fresh Transport (not http.DefaultTransport) is used
// so toggling InsecureSkipVerify for séance never mutates a shared global.
func New(timeout time.Duration, insecureSkipVerify bool) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}
