package formatter

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

type tableFormatter struct{}

func (f *tableFormatter) Write(w io.Writer, headers []string, rows [][]string) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	fmt.Fprintln(tw, strings.Join(headers, "\t"))

	seps := make([]string, len(headers))
	for i, h := range headers {
		maxLen := len(h)
		for _, row := range rows {
			if i < len(row) && len(row[i]) > maxLen {
				maxLen = len(row[i])
			}
		}
		seps[i] = strings.Repeat("-", maxLen)
	}
	fmt.Fprintln(tw, strings.Join(seps, "\t"))

	for _, row := range rows {
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}

	return tw.Flush()
}
