package subdomainbrute

import (
	"Findyou.WorkFlow/common/loadyaml"
	"github.com/projectdiscovery/gologger"
	"testing"
)

func TestSubdomainBrute(t *testing.T) {
	loadyaml.Loadyaml()
	err := SubdomainBrute([]string{"xiaohongshu.com"})
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
}
