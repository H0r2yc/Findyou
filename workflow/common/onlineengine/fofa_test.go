package onlineengine

import (
	"github.com/projectdiscovery/gologger"
	"testing"
)

func TestSearchFOFACore(t *testing.T) {
	result := SearchFOFACore("xxx", "xxx", 9000, 100)
	gologger.Info().Msg(result.Targets[0])
}
