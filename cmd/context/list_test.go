package contextcli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"rocketvault/common"
	"rocketvault/internal/formatter"
)

// ctxWithFormatter attaches a table Formatter to ctx the way
// persistentPreRun does in the real CLI, so InitContextList's RunE (which
// reads common.OutputFormatterKey out of cmd.Context()) has one to write
// through -- matching the ctxWithFormatter helper pattern used by other
// cmd/* packages' tests (e.g. cmd/secrets/create_test.go).
func ctxWithFormatter(ctx context.Context) context.Context {
	fmtr, _ := formatter.New(formatter.FormatTable)
	return context.WithValue(ctx, common.OutputFormatterKey, fmtr)
}

// TestContextList_OutputIsSortedByName is the regression test for M9
// (2026-08-17 final review): common.ListContexts() returns a map, so
// iterating it directly produced nondeterministic row order. Save contexts
// in reverse-alphabetical insertion order and verify the rendered table
// still comes out alphabetical.
func TestContextList_OutputIsSortedByName(t *testing.T) {
	common.SessionBaseDir = filepath.Join(t.TempDir(), "sessions")

	if err := common.AddContext("zulu", common.Context{Server: "https://zulu.example.com"}); err != nil {
		t.Fatalf("AddContext(zulu): %v", err)
	}
	if err := common.AddContext("alpha", common.Context{Server: "https://alpha.example.com"}); err != nil {
		t.Fatalf("AddContext(alpha): %v", err)
	}
	if err := common.AddContext("mid", common.Context{Server: "https://mid.example.com"}); err != nil {
		t.Fatalf("AddContext(mid): %v", err)
	}

	parent := &cobra.Command{Use: "context"}
	InitContextList(parent)
	parent.SetContext(ctxWithFormatter(context.Background()))

	buf := &strings.Builder{}
	parent.SetOut(buf)
	parent.SetArgs([]string{"list"})
	if err := parent.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	out := buf.String()
	iAlpha := strings.Index(out, "alpha")
	iMid := strings.Index(out, "mid")
	iZulu := strings.Index(out, "zulu")
	if iAlpha == -1 || iMid == -1 || iZulu == -1 {
		t.Fatalf("expected all three context names in output, got:\n%s", out)
	}
	if iAlpha >= iMid || iMid >= iZulu {
		t.Fatalf("expected alphabetical row order (alpha, mid, zulu), got:\n%s", out)
	}
}
