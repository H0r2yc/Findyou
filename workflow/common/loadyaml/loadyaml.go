package loadyaml

import (
	"Findyou.WorkFlow/common/utils"
	"Findyou.WorkFlow/common/workflowstruct"
	_ "embed"
	"github.com/projectdiscovery/gologger"
	"gopkg.in/yaml.v3"
)

//go:embed yaml/dir.yaml
var EmbedDirDBData string

// TODO 先不管主动探测
func ReadDirYml() {
	// 读取dir.yaml内容
	fps := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(EmbedDirDBData), &fps)
	if err != nil {
		return
	}

	workflowstruct.Dirs = make(map[string][]string)
	for productName, pathsInterfaces := range fps {
		for _, pathsInterface := range pathsInterfaces.([]interface{}) {
			p := pathsInterface.(string)
			_, ok := workflowstruct.Dirs[p]
			if ok {
				workflowstruct.Dirs[p] = append(workflowstruct.Dirs[p], productName)
				workflowstruct.Dirs[p] = utils.RemoveDuplicateElement(workflowstruct.Dirs[p])
			} else {
				workflowstruct.Dirs[p] = []string{productName}
			}
		}
	}
}

//go:embed yaml/web_fingerprint_v3.json
var EmbedFingerData string

func LoadFinger() {
	err := yaml.Unmarshal([]byte(EmbedFingerData), &workflowstruct.FingerPrints)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
}

func Loadyaml() {
	ReadDirYml()
	LoadFinger()
	if len(workflowstruct.Dirs) == 0 {
		gologger.Fatal().Msg("请检查主动指纹探测数据库是否正常。")
	}
	//添加自定义的目录作为域名爆破
	appconfig := utils.GetAppConf()
	for _, dir := range appconfig.Fingerprint.CustomDir {
		workflowstruct.Dirs[dir] = []string{"common"}
	}
	gologger.Info().Msgf("目录扫描数据正常，共: %d 条\n", len(workflowstruct.Dirs))
	if len(workflowstruct.FingerPrints) == 0 {
		gologger.Fatal().Msg("请检查指纹数据库是否正常，是否正确放置config文件夹。")
	}
	gologger.Info().Msgf("YAML指纹数据: %d 条\n", len(workflowstruct.FingerPrints))
}
