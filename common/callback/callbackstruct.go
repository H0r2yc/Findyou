package callback

import (
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"time"
)

// ResultEvent is a wrapped result event for a single nuclei output.
type ResultEvent struct {
	// Template is the relative filename for the template
	Template string `json:"template,omitempty"`
	// TemplateURL is the URL of the template for the result inside the nuclei
	// templates repository if it belongs to the repository.
	TemplateURL string `json:"template-url,omitempty"`
	// TemplateID is the ID of the template for the result.
	TemplateID string `json:"template-id"`
	// TemplatePath is the path of template
	TemplatePath string `json:"template-path,omitempty"`
	// TemplateEncoded is the base64 encoded template
	TemplateEncoded string `json:"template-encoded,omitempty"`
	// Info contains information block of the template for the result.
	Info model.Info `json:"info,inline"`
	// MatcherName is the name of the matcher matched if any.
	MatcherName string `json:"matcher-name,omitempty"`
	// ExtractorName is the name of the extractor matched if any.
	ExtractorName string `json:"extractor-name,omitempty"`
	// Type is the type of the result event.
	Type string `json:"type"`
	// Host is the host input on which match was found.
	Host string `json:"host,omitempty"`
	// Port is port of the host input on which match was found (if applicable).
	Port string `json:"port,omitempty"`
	// Scheme is the scheme of the host input on which match was found (if applicable).
	Scheme string `json:"scheme,omitempty"`
	// URL is the Base URL of the host input on which match was found (if applicable).
	URL string `json:"url,omitempty"`
	// Path is the path input on which match was found.
	Path string `json:"path,omitempty"`
	// Matched contains the matched input in its transformed form.
	Matched string `json:"matched-at,omitempty"`
	// ExtractedResults contains the extraction result from the inputs.
	ExtractedResults []string `json:"extracted-results,omitempty"`
	// Request is the optional, dumped request for the match.
	Request string `json:"request,omitempty"`
	// Response is the optional, dumped response for the match.
	Response string `json:"response,omitempty"`
	// Packet is the optional, dumped requests and responses for the match. The request and response are one-to-one.
	Packet map[int]RequestResponsePair `json:"packet,omitempty"`
	// Metadata contains any optional metadata for the event
	Metadata map[string]interface{} `json:"meta,omitempty"`
	// IP is the IP address for the found result event.
	IP string `json:"ip,omitempty"`
	// Timestamp is the time the result was found at.
	Timestamp time.Time `json:"timestamp"`
	// Interaction is the full details of interactsh interaction.
	Interaction *server.Interaction `json:"interaction,omitempty"`
	// CURLCommand is an optional curl command to reproduce the request
	// Only applicable if the report is for HTTP.
	CURLCommand string `json:"curl-command,omitempty"`
	// MatcherStatus is the status of the match
	MatcherStatus bool `json:"matcher-status"`
	// Lines is the line count for the specified match
	Lines []int `json:"matched-line,omitempty"`

	FileToIndexPosition map[string]int `json:"-"`
	Error               string         `json:"error,omitempty"`
}

type RequestResponsePair struct {
	Request  string
	Response string
}
