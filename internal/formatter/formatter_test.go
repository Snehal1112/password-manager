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

func TestJSONFormatter_Output(t *testing.T) {
	f := &jsonFormatter{}
	var buf bytes.Buffer
	headers := []string{"id", "name"}
	rows := [][]string{
		{"abc-123", "my-key"},
		{"def-456", "other-key"},
	}
	err := f.Write(&buf, headers, rows)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{`"id"`, `"abc-123"`, `"name"`, `"other-key"`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in JSON output, got:\n%s", want, out)
		}
	}
}

func TestJSONFormatter_Empty(t *testing.T) {
	f := &jsonFormatter{}
	var buf bytes.Buffer
	err := f.Write(&buf, []string{"id"}, [][]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Errorf("expected [] for empty rows, got: %q", buf.String())
	}
}

func TestYAMLFormatter_Output(t *testing.T) {
	f := &yamlFormatter{}
	var buf bytes.Buffer
	headers := []string{"id", "name"}
	rows := [][]string{
		{"abc-123", "my-key"},
	}
	err := f.Write(&buf, headers, rows)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"id:", "abc-123", "name:", "my-key"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in YAML output, got:\n%s", want, out)
		}
	}
}

func TestYAMLFormatter_Empty(t *testing.T) {
	f := &yamlFormatter{}
	var buf bytes.Buffer
	err := f.Write(&buf, []string{"id"}, [][]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := strings.TrimSpace(buf.String())
	if out != "[]" && out != "{}" && out != "" {
		t.Errorf("unexpected output for empty rows: %q", out)
	}
}

func TestNew_ValidFormats(t *testing.T) {
	for _, f := range []Format{FormatTable, FormatJSON, FormatYAML} {
		got, err := New(f)
		if err != nil {
			t.Errorf("New(%q) unexpected error: %v", f, err)
		}
		if got == nil {
			t.Errorf("New(%q) returned nil formatter", f)
		}
	}
}

func TestNew_InvalidFormat(t *testing.T) {
	_, err := New("csv")
	if err == nil {
		t.Error("expected error for unsupported format, got nil")
	}
}
