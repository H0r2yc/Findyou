package loadyaml

import (
	"Findyou.WorkFlow/common/workflowstruct"
	_ "embed"
	"github.com/projectdiscovery/gologger"
	"gopkg.in/yaml.v3"
)

//go:embed yaml/web_fingerprint_v3.json
var EmbedFingerData string

func LoadFinger() {
	err := yaml.Unmarshal([]byte(EmbedFingerData), &workflowstruct.FingerPrints)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
}

//go:embed yaml/web_activefingerprint.json
var EmbedActiveFingerData string

func LoadActiveFinger() {
	err := yaml.Unmarshal([]byte(EmbedActiveFingerData), &workflowstruct.ActiveFingerPrints)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
}

func Loadyaml() {
	LoadFinger()
	LoadActiveFinger()
	if len(workflowstruct.FingerPrints) == 0 {
		gologger.Fatal().Msg("请检查指纹数据库是否正常，是否正确放置config文件夹。")
	}
	gologger.Info().Msgf("YAML被动指纹数据: %d 条\n", len(workflowstruct.FingerPrints))
	gologger.Info().Msgf("YAML主动指纹数据: %d 条\n", len(workflowstruct.ActiveFingerPrints))
}
