package onlineengine

import (
	"github.com/projectdiscovery/gologger"
	"testing"
)

func TestSearchFOFACore(t *testing.T) {
	result := SearchFOFACore("domain=\"mucfc.com\" && country=\"CN\" && region!=\"HK\" && region!=\"TW\"", "yiheng6221@163.com:73a981a7b5b4959fa50588051444021c", 9000, 100)
	gologger.Info().Msg(result.Targets[0])
}
