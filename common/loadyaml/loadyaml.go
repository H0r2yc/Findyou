package loadyaml

import (
	"Findyou/common/config"
	"Findyou/common/utils"
	_ "embed"
	"github.com/projectdiscovery/gologger"
	"gopkg.in/yaml.v3"
	"strings"
)

//go:embed yaml/dir.yaml
var EmbedDirDBData string

func ReadDirYml() {
	// 读取dir.yaml内容
	fps := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(EmbedDirDBData), &fps)
	if err != nil {
		return
	}

	config.Dirs = make(map[string][]string)
	for productName, pathsInterfaces := range fps {
		for _, pathsInterface := range pathsInterfaces.([]interface{}) {
			p := pathsInterface.(string)
			_, ok := config.Dirs[p]
			if ok {
				config.Dirs[p] = append(config.Dirs[p], productName)
				config.Dirs[p] = utils.RemoveDuplicateElement(config.Dirs[p])
			} else {
				config.Dirs[p] = []string{productName}
			}
		}
	}
}

//go:embed yaml/finger.yaml
var EmbedFingerData string

func LoadFinger() {
	fps := make(map[string]interface{})
	err := yaml.Unmarshal([]byte(EmbedFingerData), &fps)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	m := make(map[string][]string)

	for productName, rulesInterface := range fps {
		for _, ruleInterface := range rulesInterface.([]interface{}) {
			ruleL := ruleInterface.(string)
			_, ok := m[productName]
			if ok {
				f, _ := m[productName]
				if utils.GetItemInArray(f, ruleL) == -1 {
					f = append(f, ruleL)
				}
				m[productName] = f
			} else {
				m[productName] = []string{ruleL}
			}
		}
	}

	for productName, ruleLs := range m {
		for _, ruleL := range ruleLs {
			config.Fingerprints = append(config.Fingerprints, config.FingerPEntity{ProductName: productName, Rule: ParseRule(ruleL), AllString: ruleL})
		}
	}

}

func ParseRule(rule string) []config.RuleData {
	var result []config.RuleData
	empty := config.RuleData{}

	for {
		data := getRuleData(rule)
		if data == empty {
			break
		}
		result = append(result, data)
		rule = rule[:data.Start] + "T" + rule[data.End:]
	}
	return result
}

func getRuleData(rule string) config.RuleData {
	if !strings.Contains(rule, "=\"") {
		return config.RuleData{}
	}
	pos := strings.Index(rule, "=\"")
	op := 0
	if rule[pos-1] == 33 {
		op = 1
	} else if rule[pos-1] == 61 {
		op = 2
	} else if rule[pos-1] == 62 {
		op = 3
	} else if rule[pos-1] == 60 {
		op = 4
	} else if rule[pos-1] == 126 {
		op = 5
	}

	start := 0
	ti := 0
	if op > 0 {
		ti = 1
	}
	for i := pos - 1 - ti; i >= 0; i-- {
		if (rule[i] > 122 || rule[i] < 97) && rule[i] != 95 {
			start = i + 1
			break
		}

	}
	key := rule[start : pos-ti]

	end := pos + 2
	for i := pos + 2; i < len(rule)-1; i++ {
		if rule[i] != 92 && rule[i+1] == 34 {
			end = i + 2
			break
		}
	}
	value := rule[pos+2 : end-1]
	all := rule[start:end]

	return config.RuleData{Start: start, End: end, Op: int16(op), Key: key, Value: value, All: all}
}

func Loadyaml() {
	ReadDirYml()
	LoadFinger()
	if len(config.Dirs) == 0 {
		gologger.Fatal().Msg("请检查主动指纹探测数据库是否正常。")
	}
	gologger.Info().Msgf("目录扫描数据正常，共: %d 条\n", len(config.Dirs))
	if len(config.Fingerprints) == 0 {
		gologger.Fatal().Msg("请检查指纹数据库是否正常，是否正确放置config文件夹。")
	}
	gologger.Info().Msgf("YAML指纹数据: %d 条\n", len(config.Fingerprints))
}
