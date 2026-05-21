package main

import (
	"encoding/json"
	"net/http"
)

// SecretStatus records whether a secret was successfully loaded at startup.
type SecretStatus struct {
	Loaded bool   `json:"loaded"`
	Masked string `json:"masked,omitempty"`
	Error  string `json:"error,omitempty"`
}

// StatusResponse is the payload returned by GET /status.
type StatusResponse struct {
	VaultURL            string                  `json:"vault_url"`
	ClientID            string                  `json:"client_id"`
	Secrets             map[string]SecretStatus `json:"secrets"`
	FrontendConfig      map[string]any          `json:"frontend_config"`
	FrontendConfigError string                  `json:"frontend_config_error,omitempty"`
	StartupError        string                  `json:"startup_error,omitempty"`
}

// Server holds the in-memory state populated at startup.
type Server struct {
	status StatusResponse
	listen string
}

// NewServer creates a Server with the given startup state.
func NewServer(status StatusResponse, listen string) *Server {
	return &Server{status: status, listen: listen}
}

// Start registers routes and blocks serving HTTP.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/status", s.handleStatus)
	return http.ListenAndServe(s.listen, mux)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"}) //nolint:errcheck
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.status) //nolint:errcheck
}

// maskSecret applies the masking rule:
// empty → "(empty)", len ≤ 4 → "***", len > 4 → first 4 chars + "***"
func maskSecret(v string) string {
	if v == "" {
		return "(empty)"
	}
	if len(v) <= 4 {
		return "***"
	}
	return v[:4] + "***"
}
