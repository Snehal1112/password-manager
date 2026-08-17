package cliclient

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// doGet issues a context-aware GET (satisfying the noctx linter, unlike
// client.Get) and closes the response body once the caller returns
// (satisfying bodyclose) -- shared by the tests below, all of which only
// care about the returned error, not the response body's contents.
func doGet(t *testing.T, client *http.Client, url string) error {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		defer resp.Body.Close() //nolint:errcheck
	}
	return err
}

func TestNewHTTPClient_DefaultVerification_RejectsSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	client, err := NewHTTPClient(HTTPClientOptions{})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	if err := doGet(t, client, srv.URL); err == nil {
		t.Fatal("expected TLS verification error against a self-signed server, got nil")
	}
}

func TestNewHTTPClient_CACertPath_AcceptsMatchingServer(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	certPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := srv.Certificate().Raw
	os.WriteFile(certPath, pemEncode(pemBytes), 0600)

	client, err := NewHTTPClient(HTTPClientOptions{CACertPath: certPath})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	if err := doGet(t, client, srv.URL); err != nil {
		t.Fatalf("expected success trusting the test server's own cert, got: %v", err)
	}
}

func TestNewHTTPClient_InsecureSkipVerify_AcceptsAnything(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	client, err := NewHTTPClient(HTTPClientOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	if err := doGet(t, client, srv.URL); err != nil {
		t.Fatalf("expected success with InsecureSkipVerify, got: %v", err)
	}
}

func pemEncode(der []byte) []byte {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return pem.EncodeToMemory(block)
}
