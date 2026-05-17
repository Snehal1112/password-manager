package formatter

import (
	"bytes"
	"strings"
	"testing"
)

func TestTableFormatter_Empty(t *testing.T) {
	f := &tableFormatter{}
	var buf bytes.Buffer
	err := f.Write(&buf, []string{"ID", "Name"}, [][]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "ID") || !strings.Contains(out, "Name") {
		t.Errorf("expected headers in output, got: %q", out)
	}
}

func TestTableFormatter_MultiRow(t *testing.T) {
	f := &tableFormatter{}
	var buf bytes.Buffer
	headers := []string{"ID", "Name", "Type"}
	rows := [][]string{
		{"abc-123", "my-key", "RSA"},
		{"def-456", "other-key", "ECDSA"},
	}
	err := f.Write(&buf, headers, rows)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"ID", "Name", "Type", "abc-123", "my-key", "RSA", "def-456", "other-key", "ECDSA"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output, got:\n%s", want, out)
		}
	}
}

func TestTableFormatter_SeparatorLine(t *testing.T) {
	f := &tableFormatter{}
	var buf bytes.Buffer
	err := f.Write(&buf, []string{"ID"}, [][]string{{"val"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) < 3 {
		t.Errorf("expected at least 3 lines (header, separator, data), got %d:\n%s", len(lines), buf.String())
	}
}
