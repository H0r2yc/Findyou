package onlineengine

import (
	"github.com/projectdiscovery/gologger"
	"testing"
)

func TestSearchFOFACore(t *testing.T) {

	result := SearchFOFACore("domain=\"mucfc.com\" && country=\"CN\" && region!=\"HK\" && region!=\"TW\"", "yiheng6221@163.com:093208d32a4b0202b925240b81e9b739", 9000, 100)
	gologger.Info().Msg(result.Targets[0])
}
