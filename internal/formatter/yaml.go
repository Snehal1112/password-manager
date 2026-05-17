package formatter

import (
	"io"

	"gopkg.in/yaml.v3"
)

type yamlFormatter struct{}

func (f *yamlFormatter) Write(w io.Writer, headers []string, rows [][]string) error {
	result := make([]map[string]string, 0, len(rows))
	for _, row := range rows {
		obj := make(map[string]string, len(headers))
		for i, h := range headers {
			if i < len(row) {
				obj[h] = row[i]
			}
		}
		result = append(result, obj)
	}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(result); err != nil {
		return err
	}
	return enc.Close()
}
