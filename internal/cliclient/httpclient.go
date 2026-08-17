package cliclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// HTTPClientOptions configures the shared remote HTTP client's TLS trust.
type HTTPClientOptions struct {
	CACertPath         string // --ca-cert / ROCKETVAULT_CA_CERT
	InsecureSkipVerify bool   // --insecure-skip-verify
}

// NewHTTPClient builds the *http.Client every remote*Client implementation
// uses, honoring the TLS trust options above. A non-empty CACertPath is
// added to the system trust pool. InsecureSkipVerify disables certificate
// verification entirely — callers must have already warned the user via
// WarnIfInsecure before calling this.
func NewHTTPClient(opts HTTPClientOptions) (*http.Client, error) {
	tlsConfig := &tls.Config{}

	if opts.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	} else if opts.CACertPath != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pemBytes, err := os.ReadFile(opts.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert %q: %w", opts.CACertPath, err)
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no valid certificates found in %q", opts.CACertPath)
		}
		tlsConfig.RootCAs = pool
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}, nil
}

// WarnIfInsecure prints a prominent warning to stderr when
// InsecureSkipVerify is set. Must be called once per invocation before any
// request is made — never silently.
func WarnIfInsecure(opts HTTPClientOptions) {
	if opts.InsecureSkipVerify {
		fmt.Fprintln(os.Stderr, "WARNING: TLS certificate verification is DISABLED (--insecure-skip-verify). Do not use against an untrusted network.")
	}
}
