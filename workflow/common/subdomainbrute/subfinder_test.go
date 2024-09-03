package subdomainbrute

import (
	"Findyou.WorkFlow/common/loadyaml"
	"github.com/projectdiscovery/gologger"
	"testing"
)

func TestSubfinder(t *testing.T) {
	loadyaml.Loadyaml()
	_, err := subfinder("xiaohongshu.com")
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
}
