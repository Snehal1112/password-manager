package logging

import (
	"bytes"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// YAMLFormatter is a custom logrus formatter that outputs logs in YAML format
type YAMLFormatter struct {
	TimestampFormat string
	PrettyPrint     bool
}

// Format implements the logrus.Formatter interface
func (f *YAMLFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	data := map[string]interface{}{
		"time":  entry.Time.Format(f.TimestampFormat),
		"level": entry.Level.String(),
		"msg":   entry.Message,
	}
	// Add any additional fields
	for k, v := range entry.Data {
		data[k] = v
	}

	var b bytes.Buffer
	encoder := yaml.NewEncoder(&b)
	// encoder.SetIndent(2) // Set indentation for pretty printing (not supported in yaml.v2)
	if err := encoder.Encode(data); err != nil {
		return nil, err
	}

	// Ensure a newline at the end
	b.WriteString("\n")
	return b.Bytes(), nil
}
