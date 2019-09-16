package envtypes

import (
	"errors"
	"strings"

	"github.com/sirupsen/logrus"
)

// LogFormat is used to format logs
type LogFormat func(*logrus.Entry) ([]byte, error)

// UnmarshalText implements encoding.TextUnmarshaler for LogFormat
func (l *LogFormat) UnmarshalText(in []byte) error {
	switch strings.ToLower(string(in)) {
	case "json":
		*l = (&logrus.JSONFormatter{}).Format
	case "text":
		*l = (&logrus.TextFormatter{}).Format
	default:
		return errors.New(`invalid log format specified, supported formats are "json" and "text"`)
	}
	return nil
}

// Format implements logrus.Formatter for LogFormat
func (l LogFormat) Format(in *logrus.Entry) ([]byte, error) {
	return l(in)
}
