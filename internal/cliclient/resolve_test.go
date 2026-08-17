package cliclient

import (
	"testing"

	"rocketvault/common"
)

func TestResolveTarget_FlagWins(t *testing.T) {
	// Not strictly required here -- the flag path returns before reaching
	// common.CurrentContext() -- but set for hermeticity/defense-in-depth
	// consistency with the other tests in this file (I3, 2026-08-17 final
	// review).
	common.SessionBaseDir = t.TempDir() + "/sessions"
	t.Setenv("ROCKETVAULT_ADDR", "https://env.example.com")
	target, err := ResolveTarget("https://flag.example.com")
	if err != nil || target == nil || target.Server != "https://flag.example.com" {
		t.Fatalf("ResolveTarget(flag) = %+v, %v; want flag.example.com", target, err)
	}
}

func TestResolveTarget_EnvWinsOverContext(t *testing.T) {
	common.SessionBaseDir = t.TempDir() + "/sessions"
	common.AddContext("prod", common.Context{Server: "https://ctx.example.com"})
	common.UseContext("prod")
	t.Setenv("ROCKETVAULT_ADDR", "https://env.example.com")

	target, err := ResolveTarget("")
	if err != nil || target == nil || target.Server != "https://env.example.com" {
		t.Fatalf("ResolveTarget(\"\") = %+v, %v; want env.example.com", target, err)
	}
}

func TestResolveTarget_FallsBackToContext(t *testing.T) {
	common.SessionBaseDir = t.TempDir() + "/sessions"
	common.AddContext("prod", common.Context{Server: "https://ctx.example.com", Username: "admin", Vault: "prod-vault"})
	common.UseContext("prod")

	target, err := ResolveTarget("")
	if err != nil || target == nil || target.Server != "https://ctx.example.com" || target.Username != "admin" || target.Vault != "prod-vault" {
		t.Fatalf("ResolveTarget(\"\") = %+v, %v; want ctx.example.com/admin/prod-vault", target, err)
	}
}

func TestResolveTarget_NoneConfigured_ReturnsNil(t *testing.T) {
	common.SessionBaseDir = t.TempDir() + "/sessions"
	target, err := ResolveTarget("")
	if err != nil || target != nil {
		t.Fatalf("ResolveTarget(\"\") = %+v, %v; want nil, nil (local mode)", target, err)
	}
}
