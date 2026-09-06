package vaultcli

import (
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"rocketvault/internal/formatter"
)

// Column renders one field of T as a table cell. A []Column[T] is the single
// description of how a resource is printed: the header text and the cell that
// goes under it are declared together, so they cannot drift.
//
// Before this, every command built a []string of headers and a parallel
// []string of cells by hand, twice over for commands with a remote path --
// `secrets get` spelled the same ten headers out in two places forty lines
// apart, and `get` and `list` for the same resource each had their own copy.
type Column[T any] struct {
	Header string
	Value  func(T) string
}

// Col builds a Column from a header and a field accessor.
func Col[T any](header string, value func(T) string) Column[T] {
	return Column[T]{Header: header, Value: value}
}

// Render writes items to w through f, using cols for both the header row and
// each item's cells. A single item is just Render(w, f, cols, item).
func Render[T any](w io.Writer, f formatter.Formatter, cols []Column[T], items ...T) error {
	headers := make([]string, len(cols))
	for i, c := range cols {
		headers[i] = c.Header
	}

	rows := make([][]string, len(items))
	for i, item := range items {
		row := make([]string, len(cols))
		for j, c := range cols {
			row[j] = c.Value(item)
		}
		rows[i] = row
	}

	return f.Write(w, headers, rows)
}

// Cell helpers for the value types that appear in nearly every column set.
// They exist so the same value is never formatted two different ways in two
// commands -- times were RFC3339 everywhere already, but only by convention.

// CellTime formats a time as RFC3339.
func CellTime(t time.Time) string { return t.Format(time.RFC3339) }

// CellOptTime formats an optional time as RFC3339, rendering nil as empty.
// Replaces the two identical formatOptionalTime helpers in cmd/secrets and
// cmd/certificates.
func CellOptTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

// CellBool formats a boolean as "true"/"false".
func CellBool(b bool) string { return strconv.FormatBool(b) }

// CellInt formats an int.
func CellInt(n int) string { return strconv.Itoa(n) }

// CellCSV joins a string slice with commas, the tag format the CLI already
// accepts on input.
func CellCSV(v []string) string { return strings.Join(v, ",") }

// CellUUID formats a UUID.
func CellUUID(id uuid.UUID) string { return id.String() }
