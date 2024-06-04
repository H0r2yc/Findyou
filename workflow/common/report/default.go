package report

import (
	"strings"
)

func xssfilter(s string) string {
	s = strings.ReplaceAll(s, "<", "%3C")
	s = strings.ReplaceAll(s, ">", "%3E")
	return s
}
