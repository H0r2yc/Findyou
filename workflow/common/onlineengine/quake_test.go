package onlineengine

import (
	"github.com/projectdiscovery/gologger"
	"testing"
)

func TestSearchQUAKECore(t *testing.T) {
	result := SearchQUAKECore("xxx", "xxx", 100, 100)
	gologger.Info().Msg(result.Targets[0])
}
