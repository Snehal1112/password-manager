package formatter

import "io"

type tableFormatter struct{}

func (f *tableFormatter) Write(w io.Writer, headers []string, rows [][]string) error {
	return nil
}
