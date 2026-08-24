package mcpserver

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequireConfirmation_AllowsAnExactMatch(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())

	require.Nil(t, s.requireConfirmation("purge_item", "db-password", "db-password"),
		"a nil result means the call may proceed")
}

func TestRequireConfirmation_RefusesAMismatch(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())

	refusal := s.requireConfirmation("purge_item", "db-password", "api-key")
	require.NotNil(t, refusal)
	require.True(t, refusal.IsError)
}

func TestRequireConfirmation_RefusesAnEmptyConfirmation(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())

	refusal := s.requireConfirmation("purge_item", "db-password", "")
	require.NotNil(t, refusal)
	require.Contains(t, renderContent(refusal), "confirm")
	require.Contains(t, renderContent(refusal), "db-password",
		"the message must name what to echo, so the caller can comply in one step")
}

func TestRequireConfirmation_IsCaseSensitive(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())

	refusal := s.requireConfirmation("purge_item", "db-password", "DB-Password")
	require.NotNil(t, refusal,
		"names are case-sensitive identifiers; accepting a different case would confirm a name that does not exist")
}

func TestRequireConfirmation_TrimsSurroundingWhitespace(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())

	require.Nil(t, s.requireConfirmation("purge_item", "db-password", "  db-password  "),
		"leading whitespace is a transport artifact, not a different name")
}

func TestRequireConfirmation_IsSkippedWhenDisabled(t *testing.T) {
	f := newFakeVault(t, map[string]string{})

	cfg := destructiveConfig()
	cfg.ConfirmDestructive = false
	s := f.server(t, cfg)

	require.Nil(t, s.requireConfirmation("purge_item", "db-password", ""),
		"an operator who turned the guard off should not still be asked")
}

func TestRequireConfirmation_MismatchMessageShowsBothValues(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())

	refusal := s.requireConfirmation("purge_item", "db-password", "api-key")
	rendered := renderContent(refusal)

	require.Contains(t, rendered, "db-password")
	require.Contains(t, rendered, "api-key",
		"showing both makes a wrong target obvious rather than leaving the caller to guess")
}

func TestRequireConfirmation_NamesTheTool(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())

	refusal := s.requireConfirmation("purge_vault", "prod", "")
	require.Contains(t, renderContent(refusal), "purge_vault")
}

func TestRequireConfirmation_DoesNotWrapTheResourceName(t *testing.T) {
	f := newFakeVault(t, map[string]string{})
	s := f.server(t, destructiveConfig())

	refusal := s.requireConfirmation("purge_item", "db-password", "")
	require.NotContains(t, renderContent(refusal), "UNTRUSTED",
		"the name must be echoable verbatim; wrapping it would make the instruction impossible to follow")
	require.False(t, strings.Contains(renderContent(refusal), "<<"))
}
