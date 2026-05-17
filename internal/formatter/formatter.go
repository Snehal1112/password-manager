package formatter

import (
	"fmt"
	"io"
)

// Format is the CLI output format type.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
	FormatYAML  Format = "yaml"
)

// Formatter renders tabular data to a writer.
type Formatter interface {
	Write(w io.Writer, headers []string, rows [][]string) error
}

// New returns a Formatter for the given format.
// Returns an error if the format is not recognised.
func New(f Format) (Formatter, error) {
	switch f {
	case FormatTable:
		return &tableFormatter{}, nil
	case FormatJSON:
		return &jsonFormatter{}, nil
	case FormatYAML:
		return &yamlFormatter{}, nil
	default:
		return nil, fmt.Errorf("unsupported output format %q: must be table, json, or yaml", f)
	}
}
