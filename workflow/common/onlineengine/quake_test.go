package onlineengine

import (
	"github.com/projectdiscovery/gologger"
	"testing"
)

func TestSearchQUAKECore(t *testing.T) {
	result := SearchQUAKECore("domain:\"jsft.com\"", "035c1bd9-0ac4-4a0f-a23b-42cb8c6abb5c", 100, 100)
	gologger.Info().Msg(result.Targets[0])
}
