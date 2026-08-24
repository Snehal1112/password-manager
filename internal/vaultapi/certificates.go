package vaultapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// CertificateSummary is a certificate as it appears in a list.
//
// api.CertificateResponse carries metadata only, with no PEM and no chain, so
// nothing here needs a redacting type.
type CertificateSummary struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	Tags      []string   `json:"tags,omitempty"`
	Enabled   bool       `json:"enabled"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
}

// Certificate is a single certificate with its renewal settings.
type Certificate struct {
	CertificateSummary
	AutoRenew   bool `json:"auto_renew"`
	RenewalDays int  `json:"renewal_days"`
}

// certificateWire is the raw response shape (api/certificates.go:68).
type certificateWire struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	CreatedAt   time.Time  `json:"created_at"`
	Tags        []string   `json:"tags"`
	AutoRenew   bool       `json:"auto_renew"`
	RenewalDays int        `json:"renewal_days"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Enabled     bool       `json:"enabled"`
	NotBefore   *time.Time `json:"not_before"`
}

type certificatesListResponse struct {
	Certificates []certificateWire `json:"certificates"`
}

func (w certificateWire) summary() (CertificateSummary, error) {
	id, err := uuid.Parse(w.ID)
	if err != nil {
		return CertificateSummary{}, fmt.Errorf("vaultapi: certificate %q has an unparseable id: %w", w.Name, err)
	}
	return CertificateSummary{
		ID:        id,
		Name:      w.Name,
		Tags:      w.Tags,
		Enabled:   w.Enabled,
		CreatedAt: w.CreatedAt,
		ExpiresAt: w.ExpiresAt,
		NotBefore: w.NotBefore,
	}, nil
}

// ListCertificates returns the certificates in vault, capped at limit. The
// bool reports truncation. A limit of zero or less returns everything.
func (c *Client) ListCertificates(ctx context.Context, vault string, limit int) ([]CertificateSummary, bool, error) {
	if vault == "" {
		return nil, false, fmt.Errorf("vaultapi: vault is required to list certificates")
	}

	var response certificatesListResponse
	path := fmt.Sprintf("/api/v1/vaults/%s/certificates", vault)
	if err := c.Do(ctx, http.MethodGet, path, nil, &response); err != nil {
		return nil, false, err
	}

	truncated := limit > 0 && len(response.Certificates) > limit
	wires := response.Certificates
	if truncated {
		wires = wires[:limit]
	}

	summaries := make([]CertificateSummary, 0, len(wires))
	for _, wire := range wires {
		summary, err := wire.summary()
		if err != nil {
			return nil, false, err
		}
		summaries = append(summaries, summary)
	}
	return summaries, truncated, nil
}

// GetCertificate fetches one certificate by name or id.
func (c *Client) GetCertificate(ctx context.Context, vault, name string) (*Certificate, error) {
	if vault == "" {
		return nil, fmt.Errorf("vaultapi: vault is required to get a certificate")
	}

	id, err := c.Resolver().Resolve(ctx, vault, KindCertificates, name)
	if err != nil {
		return nil, err
	}

	var wire certificateWire
	path := fmt.Sprintf("/api/v1/vaults/%s/certificates/%s", vault, id)
	if err := c.Do(ctx, http.MethodGet, path, nil, &wire); err != nil {
		return nil, err
	}

	summary, err := wire.summary()
	if err != nil {
		return nil, err
	}
	return &Certificate{
		CertificateSummary: summary,
		AutoRenew:          wire.AutoRenew,
		RenewalDays:        wire.RenewalDays,
	}, nil
}
