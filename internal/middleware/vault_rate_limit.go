package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"rocketvault/common"
	"rocketvault/model"
)

// defaultVaultRateLimit is the per-vault request budget used when
// rate_limit.per_vault is unset or not positive. It is double the per-IP
// default so a vault served by a couple of busy clients is not throttled by
// its own ceiling before the per-IP limiter has a say.
const defaultVaultRateLimit = 600

// VaultRateLimitRecorder reports throttled vaults to a metrics backend.
// Declared here rather than imported so this package does not depend on
// internal/metrics; the Prometheus implementation satisfies it structurally.
type VaultRateLimitRecorder interface {
	RecordVaultRateLimitRejection(vaultID string)
}

// SetVaultRateLimitMetrics wires a metrics recorder for per-vault throttling.
// Optional — with no recorder set, rejections are logged but not counted.
func (m *Middleware) SetVaultRateLimitMetrics(r VaultRateLimitRecorder) {
	m.vaultLimitMetrics = r
}

// VaultRateLimitMiddleware applies a per-vault token-bucket budget, so that one
// vault's traffic cannot consume the request capacity of another. It complements
// RateLimitMiddleware rather than replacing it: the per-IP limiter stops a single
// noisy host, this stops a single noisy tenant spread across many hosts.
//
// It MUST run after VaultResolutionMiddleware — the target vault is not known
// before that. Requests on routes that resolve no vault (vault management, and
// the legacy flat resource routes) fall back to the default vault, matching
// PolicyMiddleware, so their traffic is counted against the default vault.
//
// The budget is reported under X-RateLimit-Vault-* so it cannot overwrite the
// per-IP limiter's X-RateLimit-* headers, which are written earlier in the chain.
func (m *Middleware) VaultRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health probes skip VaultResolutionMiddleware, so they have no vault of
		// their own. Counting them would let a liveness probe drain the default
		// vault's budget and throttle real traffic.
		if isHealthProbe(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Mirror PolicyMiddleware's fallback so an unresolved vault and an
		// explicit default vault share one bucket rather than splitting it.
		vaultID, _ := r.Context().Value(common.VaultIDKey).(string)
		if vaultID == "" {
			vaultID = model.DefaultVaultID
		}

		lim := m.vaultLimiter.get(vaultID)
		w.Header().Set("X-RateLimit-Vault-Limit", fmt.Sprintf("%d", m.vaultLimiter.b))
		w.Header().Set("X-RateLimit-Vault-Remaining", fmt.Sprintf("%d", max(0, int(lim.Tokens()))))
		w.Header().Set("X-RateLimit-Vault-Reset", fmt.Sprintf("%d", time.Now().Add(time.Minute).Unix()))

		if !lim.Allow() {
			if m.vaultLimitMetrics != nil {
				m.vaultLimitMetrics.RecordVaultRateLimitRejection(vaultID)
			}
			m.logger.LogAuditError("", "vault_rate_limit", "failed",
				fmt.Sprintf("Per-vault rate limit exceeded for vault %s", vaultID), nil)
			logrus.WithFields(logrus.Fields{
				"vault_id": vaultID,
				"endpoint": r.URL.Path,
				"limit":    m.vaultLimiter.b,
			}).Warn("Per-vault rate limit exceeded")
			http.Error(w, "Vault rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
