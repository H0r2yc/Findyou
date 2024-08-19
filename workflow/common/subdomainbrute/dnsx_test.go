package subdomainbrute

import (
	"Findyou.WorkFlow/common/loadyaml"
	"github.com/projectdiscovery/gologger"
	"testing"
)

func TestDnsX(t *testing.T) {
	loadyaml.Loadyaml()
	err := DnsX("ddxm.mobi")
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
}
