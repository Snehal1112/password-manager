package cliclient

import (
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNewHTTPClient_DefaultVerification_RejectsSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	client, err := NewHTTPClient(HTTPClientOptions{})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	if _, err := client.Get(srv.URL); err == nil {
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
	if _, err := client.Get(srv.URL); err != nil {
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
	if _, err := client.Get(srv.URL); err != nil {
		t.Fatalf("expected success with InsecureSkipVerify, got: %v", err)
	}
}

func pemEncode(der []byte) []byte {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return pem.EncodeToMemory(block)
}
