// Package api — unit tests for vault.go.
package api

import (
	"testing"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"

	"rocketvault/app"
	"rocketvault/internal/logging"
)

// TestInitVault_DoesNotPanic verifies that InitVault completes without panicking.
func TestInitVault_DoesNotPanic(t *testing.T) {
	router := mux.NewRouter()
	l := logrus.New()
	a := &API{
		App:        app.NewTestApp(),
		BaseRoutes: &Routes{},
		basePath:   "/api/v1",
		rootRouter: router,
		Logger:     logging.WrapLogrus(l),
	}
	a.BaseRoutes.ApiRoot = router.PathPrefix("/api/v1").Subrouter()
	a.BaseRoutes.Vault = a.BaseRoutes.ApiRoot.PathPrefix("/vault").Subrouter()

	// Must not panic — vault is currently a placeholder.
	a.InitVault()
}
