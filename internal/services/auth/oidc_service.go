package auth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCIdentity is the verified identity extracted from an OIDC ID token.
type OIDCIdentity struct {
	Subject           string
	Email             string
	PreferredUsername string
}

// oidcClaims is the subset of standard OIDC claims OIDCService reads from a
// verified ID token.
type oidcClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
}

// OIDCConfig holds OIDCService's configuration.
type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// OIDCService builds the OIDC authorization redirect and verifies the
// resulting ID token on callback.
type OIDCService interface {
	// AuthCodeURL builds the provider's authorization endpoint URL for state
	// and nonce, both of which the caller must independently store (e.g. in
	// short-lived cookies) and re-verify in HandleCallback.
	AuthCodeURL(state, nonce string) string
	// HandleCallback exchanges code for tokens and verifies the returned ID
	// token, including that its nonce claim equals expectedNonce.
	HandleCallback(ctx context.Context, code, expectedNonce string) (*OIDCIdentity, error)
}

type oidcService struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
}

// NewOIDCService fetches the provider's discovery document (a network round
// trip to issuerURL) and returns a ready-to-use OIDCService, or an error if
// the issuer is unreachable or malformed.
func NewOIDCService(ctx context.Context, cfg OIDCConfig) (OIDCService, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to discover issuer %q: %w", cfg.IssuerURL, err)
	}

	return &oidcService{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth2Config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       cfg.Scopes,
		},
	}, nil
}

// AuthCodeURL builds the provider's authorization endpoint URL.
func (s *oidcService) AuthCodeURL(state, nonce string) string {
	return s.oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce))
}

// HandleCallback exchanges code for tokens, verifies the ID token's
// signature and claims (including that its nonce matches expectedNonce), and
// returns the caller's identity.
func (s *oidcService) HandleCallback(ctx context.Context, code, expectedNonce string) (*OIDCIdentity, error) {
	token, err := s.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("oidc: code exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("oidc: token response did not include an id_token")
	}

	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: id_token verification failed: %w", err)
	}

	if idToken.Nonce != expectedNonce {
		return nil, fmt.Errorf("oidc: nonce mismatch")
	}

	var claims oidcClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: failed to parse id_token claims: %w", err)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("oidc: id_token missing sub claim")
	}

	preferredUsername := claims.PreferredUsername
	if preferredUsername == "" {
		preferredUsername = claims.Name
	}

	return &OIDCIdentity{
		Subject:           claims.Subject,
		Email:             claims.Email,
		PreferredUsername: preferredUsername,
	}, nil
}
