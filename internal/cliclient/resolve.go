// Package cliclient decides which server, if any, a CLI invocation should
// talk to. It is the shared entry point future resource-group adapters call
// to choose between local (direct database/service access) and remote
// (talking to a RocketVault API server) execution.
package cliclient

import (
	"os"

	"rocketvault/common"
)

// Target describes the resolved remote server this invocation should talk
// to. A nil *Target (with a nil error) means local mode.
type Target struct {
	Server   string
	Username string // default username from a context, if any; command flags still win
	Vault    string // default vault from a context, if any; --vault still wins
}

// ResolveTarget applies the precedence chain: an explicit --server flag
// value (pass "" if the flag wasn't set or is empty), then the
// ROCKETVAULT_ADDR environment variable, then the current named context.
// Returns (nil, nil) if none resolve — the caller is in local mode.
func ResolveTarget(serverFlag string) (*Target, error) {
	if serverFlag != "" {
		return &Target{Server: serverFlag}, nil
	}
	if server := os.Getenv("ROCKETVAULT_ADDR"); server != "" {
		return &Target{Server: server}, nil
	}
	ctx, _, err := common.CurrentContext()
	if err != nil {
		return nil, err
	}
	if ctx != nil {
		return &Target{Server: ctx.Server, Username: ctx.Username, Vault: ctx.Vault}, nil
	}
	return nil, nil
}
