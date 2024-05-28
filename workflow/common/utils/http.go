package utils

import (
	"net/url"
)

func URLParse(URLRaw string) *url.URL {
	URL, _ := url.Parse(URLRaw)
	return URL
}
