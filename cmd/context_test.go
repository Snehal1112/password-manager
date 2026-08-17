package cmd

import (
	"context"
	"os"
	"testing"

	"github.com/spf13/viper"

	"rocketvault/common"
)

// TestContextList_RealRootCmd_NoConfigNoAuth is the regression test for C1
// (2026-08-17 final review): `context` command execution must work on a
// machine with no .rocketvault.yaml and no local database at all — that is
// exactly the scenario the whole CLI-remote-server-support plan exists for.
//
// The existing cmd/context/*_test.go tests each build a synthetic
// &cobra.Command{Use: "context"} parent and call the InitContext* wiring
// function directly. That never exercises rootCmd's own
// initConfig/persistentPreRun machinery, which is exactly why this bug —
// "context" was missing from persistentPreRun's systemCmds map, and
// initConfig had no way to know a `context` command doesn't need a config
// file at all — was invisible to them. This test drives the real rootCmd
// instead, the way `rocketvault context list` actually executes.
func TestContextList_RealRootCmd_NoConfigNoAuth(t *testing.T) {
	dir := t.TempDir() // deliberately has no .rocketvault.yaml
	common.SessionBaseDir = dir + "/sessions"

	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}

	previousCfgFile := cfgFile
	cfgFile = ""
	t.Cleanup(func() { cfgFile = previousCfgFile })

	previousSettings := viper.AllSettings()
	viper.Reset()
	t.Cleanup(func() {
		viper.Reset()
		_ = viper.MergeConfigMap(previousSettings)
	})

	// initConfig runs as a cobra.OnInitialize hook, so cobra calls it with no
	// *cobra.Command argument — it determines which command is about to run
	// by re-resolving args the same way cobra's own ExecuteC does when
	// SetArgs hasn't been called (falling back to os.Args[1:]). Since this
	// test *does* call SetArgs below (needed so ExecuteContext doesn't fall
	// back to the `go test` binary's own os.Args), os.Args must be mirrored
	// to match so initConfig's resolution agrees with what will actually
	// run. In real CLI usage main.go never calls SetArgs, so the two are
	// always identical there by construction — this mirroring is purely a
	// test-harness accommodation.
	previousArgs := os.Args
	os.Args = []string{"rocketvault", "context", "list"}
	t.Cleanup(func() { os.Args = previousArgs })

	rootCmd.SetArgs([]string{"context", "list"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("`rocketvault context list` panicked (C1 regression): %v", r)
		}
	}()

	if err := rootCmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("`rocketvault context list` returned an error (should run with no config/auth): %v", err)
	}
}
