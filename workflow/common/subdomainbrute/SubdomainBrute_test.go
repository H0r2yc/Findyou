package subdomainbrute

import (
	"Findyou.WorkFlow/common/loadyaml"
	"github.com/projectdiscovery/gologger"
	"testing"
)

func TestSubdomainBrute(t *testing.T) {
	loadyaml.Loadyaml()
	err := SubdomainBrute([]string{"ddxm.mobi"})
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
}
