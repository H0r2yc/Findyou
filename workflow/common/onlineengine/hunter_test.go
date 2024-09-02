package onlineengine

import (
	"github.com/projectdiscovery/gologger"
	"testing"
)

func TestSearchHunterCore(t *testing.T) {
	result := SearchHunterCore("ip=\"221.229.247.254\" && ip.country=\"CN\" && ip.country!=\"HK\" && ip.country!=\"TW\"", "ced8fd312475a35afd76cc07ea7b54ec977216a96b7ca6e34b578d62f7f411af", 100, 100)
	gologger.Info().Msg(result.Targets[0])
}
