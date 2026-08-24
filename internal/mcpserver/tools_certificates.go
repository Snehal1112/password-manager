package mcpserver

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type listCertificatesArgs struct {
	Vault string `json:"vault,omitempty" jsonschema:"the vault to list; defaults to the server's configured vault"`
	Limit int    `json:"limit,omitempty" jsonschema:"maximum number of certificates to return; capped by the server"`
}

// certificateSummaryResult is one certificate's metadata. The API returns no
// PEM and no chain, and this type has no field for either.
type certificateSummaryResult struct {
	Name      string      `json:"name"`
	ID        string      `json:"id"`
	Enabled   bool        `json:"enabled"`
	Tags      []Untrusted `json:"tags,omitempty"`
	CreatedAt string      `json:"created_at,omitempty"`
	ExpiresAt string      `json:"expires_at,omitempty"`
}

type listCertificatesResult struct {
	Vault        string                     `json:"vault"`
	Certificates []certificateSummaryResult `json:"certificates"`
	Truncated    bool                       `json:"truncated"`
	Note         string                     `json:"note,omitempty"`
}

type getCertificateArgs struct {
	Name  string `json:"name" jsonschema:"the certificate's name, or its id"`
	Vault string `json:"vault,omitempty" jsonschema:"the vault to read from; defaults to the server's configured vault"`
}

// certificatePolicyResult describes issuance and renewal.
//
// Subject and SANs are operator-supplied free text, so both are wrapped.
type certificatePolicyResult struct {
	ValidityMonths   int       `json:"validity_months"`
	KeyType          string    `json:"key_type"`
	KeySize          int       `json:"key_size,omitempty"`
	Curve            string    `json:"curve,omitempty"`
	Subject          Untrusted `json:"subject"`
	SANs             Untrusted `json:"sans,omitempty"`
	AutoRenew        bool      `json:"auto_renew"`
	DaysBeforeExpiry int       `json:"days_before_expiry"`
	IssuerName       Untrusted `json:"issuer_name,omitempty"`
}

type getCertificateResult struct {
	Vault       string                   `json:"vault"`
	Name        string                   `json:"name"`
	ID          string                   `json:"id"`
	Enabled     bool                     `json:"enabled"`
	AutoRenew   bool                     `json:"auto_renew"`
	RenewalDays int                      `json:"renewal_days"`
	Tags        []Untrusted              `json:"tags,omitempty"`
	CreatedAt   string                   `json:"created_at,omitempty"`
	ExpiresAt   string                   `json:"expires_at,omitempty"`
	Policy      *certificatePolicyResult `json:"policy,omitempty"`
}

// registerCertificatesReadTools adds the read-tier certificate tools.
func registerCertificatesReadTools(s *Server) {
	registerIf(s, TierRead, "list_certificates",
		"List the certificates in a vault, with their expiry and renewal settings.",
		Annotations{ReadOnly: true, Idempotent: true}, s.handleListCertificates)

	registerIf(s, TierRead, "get_certificate",
		"Get a certificate's metadata and issuance policy, including subject, SANs and renewal settings.",
		Annotations{ReadOnly: true, Idempotent: true}, s.handleGetCertificate)
}

func (s *Server) handleListCertificates(ctx context.Context, _ *mcp.CallToolRequest, args listCertificatesArgs) (*mcp.CallToolResult, listCertificatesResult, error) {
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), listCertificatesResult{}, nil
	}

	limit := s.effectiveLimit(args.Limit)
	summaries, truncated, err := s.client.ListCertificates(ctx, vault, limit)
	if err != nil {
		return errorResult("could not list certificates in vault %q: %s", vault, err), listCertificatesResult{}, nil
	}

	certificates := make([]certificateSummaryResult, 0, len(summaries))
	for _, summary := range summaries {
		entry := certificateSummaryResult{
			Name:      summary.Name,
			ID:        summary.ID.String(),
			Enabled:   summary.Enabled,
			Tags:      WrapAll(summary.Tags),
			CreatedAt: summary.CreatedAt.Format(time.RFC3339),
		}
		if summary.ExpiresAt != nil {
			entry.ExpiresAt = summary.ExpiresAt.Format(time.RFC3339)
		}
		certificates = append(certificates, entry)
	}

	return nil, listCertificatesResult{
		Vault:        vault,
		Certificates: certificates,
		Truncated:    truncated,
		Note:         truncationNote(truncated, limit),
	}, nil
}

func (s *Server) handleGetCertificate(ctx context.Context, _ *mcp.CallToolRequest, args getCertificateArgs) (*mcp.CallToolResult, getCertificateResult, error) {
	if args.Name == "" {
		return errorResult("get_certificate requires a name"), getCertificateResult{}, nil
	}
	vault, err := s.ResolveVault(args.Vault)
	if err != nil {
		return errorResult("%s", err), getCertificateResult{}, nil
	}

	certificate, err := s.client.GetCertificate(ctx, vault, args.Name)
	if err != nil {
		return errorResult("could not get certificate %q in vault %q: %s", args.Name, vault, err), getCertificateResult{}, nil
	}

	result := getCertificateResult{
		Vault:       vault,
		Name:        certificate.Name,
		ID:          certificate.ID.String(),
		Enabled:     certificate.Enabled,
		AutoRenew:   certificate.AutoRenew,
		RenewalDays: certificate.RenewalDays,
		Tags:        WrapAll(certificate.Tags),
		CreatedAt:   certificate.CreatedAt.Format(time.RFC3339),
	}
	if certificate.ExpiresAt != nil {
		result.ExpiresAt = certificate.ExpiresAt.Format(time.RFC3339)
	}

	// The policy is supplementary; many certificates have none.
	if policy, err := s.client.GetCertificatePolicy(ctx, vault, args.Name); err == nil && policy != nil {
		result.Policy = &certificatePolicyResult{
			ValidityMonths:   policy.ValidityMonths,
			KeyType:          policy.KeyType,
			KeySize:          policy.KeySize,
			Curve:            policy.Curve,
			Subject:          Wrap(policy.Subject),
			SANs:             Wrap(policy.SANs),
			AutoRenew:        policy.AutoRenew,
			DaysBeforeExpiry: policy.DaysBeforeExpiry,
			IssuerName:       Wrap(policy.IssuerName),
		}
	}
	return nil, result, nil
}
