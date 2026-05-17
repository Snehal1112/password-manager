package model

import (
	"encoding/json"
	"io"
	"time"

	"github.com/google/uuid"
)

// OAuth2Client represents a machine-to-machine authentication client.
type OAuth2Client struct {
	ID           uuid.UUID  `json:"id"`
	Name         string     `json:"name"`
	ClientSecret string     `json:"client_secret,omitempty"`
	Description  string     `json:"description"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

type CreateOAuth2ClientRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func CreateOAuth2ClientRequestFromJson(data io.Reader) (*CreateOAuth2ClientRequest, error) {
	var r CreateOAuth2ClientRequest
	return &r, json.NewDecoder(data).Decode(&r)
}

type OAuth2ClientResponse struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	ClientSecret string     `json:"client_secret,omitempty"`
	Description  string     `json:"description"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

func (r *OAuth2ClientResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}

type ListOAuth2ClientsResponse struct {
	Clients []OAuth2ClientResponse `json:"clients"`
	Total   int                    `json:"total"`
}

func (r *ListOAuth2ClientsResponse) ToJson() string {
	b, _ := json.Marshal(r)
	return string(b)
}
