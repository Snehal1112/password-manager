package logging

import (
	"reflect"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestYAMLFormatter_Format(t *testing.T) {
	type fields struct {
		TimestampFormat string
		PrettyPrint     bool
	}
	type args struct {
		entry *logrus.Entry
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &YAMLFormatter{
				TimestampFormat: tt.fields.TimestampFormat,
				PrettyPrint:     tt.fields.PrettyPrint,
			}
			got, err := f.Format(tt.args.entry)
			if (err != nil) != tt.wantErr {
				t.Errorf("YAMLFormatter.Format() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("YAMLFormatter.Format() = %v, want %v", got, tt.want)
			}
		})
	}
}
