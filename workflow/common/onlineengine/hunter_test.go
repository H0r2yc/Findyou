package onlineengine

import (
	"github.com/projectdiscovery/gologger"
	"testing"
)

func TestSearchHunterCore(t *testing.T) {
	result := SearchHunterCore("xxx", "xxx", 100, 100)
	gologger.Info().Msg(result.Targets[0])
}
