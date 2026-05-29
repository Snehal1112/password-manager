package cmd

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
)

func TestResolveVault_Precedence(t *testing.T) {
	// Flag wins over env.
	c1 := &cobra.Command{}
	c1.Flags().String("vault", "", "")
	c1.Flags().Set("vault", "flagvault")
	t.Setenv("ROCKETVAULT_VAULT", "envvault")
	if got := resolveVault(c1); got != "flagvault" {
		t.Fatalf("flag should win, got %q", got)
	}
	// Env when no flag.
	c2 := &cobra.Command{}
	c2.Flags().String("vault", "", "")
	t.Setenv("ROCKETVAULT_VAULT", "envvault")
	if got := resolveVault(c2); got != "envvault" {
		t.Fatalf("env should win when no flag, got %q", got)
	}
	// Built-in default when nothing set.
	c3 := &cobra.Command{}
	c3.Flags().String("vault", "", "")
	os.Unsetenv("ROCKETVAULT_VAULT")
	if got := resolveVault(c3); got != "default" {
		t.Fatalf("should fall back to default, got %q", got)
	}
}
