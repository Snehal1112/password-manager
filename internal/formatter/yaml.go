package formatter

import "io"

type yamlFormatter struct{}

func (f *yamlFormatter) Write(w io.Writer, headers []string, rows [][]string) error {
	return nil
}
