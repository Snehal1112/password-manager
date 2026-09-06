package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Command flags must be read through cmd.Flags(), never through the global
// viper registry.
//
// viper.BindPFlag stores one flag per key process-wide, so two commands
// binding the same key silently overwrite each other: cmd/keys/list.go and
// cmd/keys/update.go both bound "tags", update's Init ran last (cmd/keys.go),
// and `keys list --tags prod` read update's unset flag and dropped the filter
// with no error. viper.AutomaticEnv() compounds it -- an unnamespaced key
// like "tags" or "password" is also satisfiable from the environment and
// from .rocketvault.yaml, so config could feed a command's flags.
//
// Real config keys (jwt.expiry, frontend.public_api_url, and root.go's
// "vault") stay on viper deliberately; only per-command flag bindings are
// banned. The exemption below is the root --vault flag, which is genuinely
// config-backed (--vault > ROCKETVAULT_VAULT > config > "default") and is
// bound exactly once.
func TestNoCommandFlagsBoundToGlobalViper(t *testing.T) {
	const rootVaultBinding = `viper.BindPFlag("vault", rootCmd.PersistentFlags().Lookup("vault"))`

	var offenders []string
	err := filepath.Walk("..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Only the CLI tree is in scope.
			if info.Name() != "cmd" && !strings.Contains(path, "cmd") {
				if path != ".." {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path) //nolint:gosec // test-only walk of the repo's own tree
		if readErr != nil {
			return readErr
		}
		for i, line := range strings.Split(string(src), "\n") {
			if !strings.Contains(line, "viper.BindPFlag(") {
				continue
			}
			if strings.Contains(line, rootVaultBinding) {
				continue
			}
			offenders = append(offenders, filepath.ToSlash(path)+":"+itoa(i+1)+": "+strings.TrimSpace(line))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the cmd tree: %v", err)
	}

	if len(offenders) > 0 {
		t.Errorf("command flags bound to global viper (read them via cmd.Flags() instead):\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// Demonstrates the failure mode the rule above prevents: the second bind wins,
// so the first command's flag value is unreachable through viper.
func TestViperBindPFlag_LastBindingWins(t *testing.T) {
	v := viper.New()

	list := pflag.NewFlagSet("list", pflag.ContinueOnError)
	list.String("tags", "", "")
	update := pflag.NewFlagSet("update", pflag.ContinueOnError)
	update.String("tags", "", "")

	// Init order in cmd/keys.go: InitKeysList, then InitKeysUpdate.
	if err := v.BindPFlag("tags", list.Lookup("tags")); err != nil {
		t.Fatal(err)
	}
	if err := v.BindPFlag("tags", update.Lookup("tags")); err != nil {
		t.Fatal(err)
	}

	if err := list.Set("tags", "prod"); err != nil {
		t.Fatal(err)
	}

	if got := v.GetString("tags"); got != "" {
		t.Fatalf("expected the collision to swallow list's value, got %q; "+
			"if viper changed this behaviour the guard test above can be relaxed", got)
	}
	if got, _ := list.GetString("tags"); got != "prod" {
		t.Fatalf("reading through the flag set is the fix, but got %q", got)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
