package formatter

import "io"

type jsonFormatter struct{}

func (f *jsonFormatter) Write(w io.Writer, headers []string, rows [][]string) error {
	return nil
}
