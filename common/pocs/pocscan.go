package pocs

import (
	"Findyou/common/callnuclei"
	"Findyou/common/config"
	"Findyou/common/report"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"strconv"
	"strings"
)

func PocScan() {
	// 调用Nuclei
	var nucleiResults []output.ResultEvent
	TargetAndPocsName, count := GetPocs(config.WorkFlowDB)
	if count > 0 {
		nucleiResults = callnuclei.CallNuclei(TargetAndPocsName,
			config.GlobalConfig.HTTPProxy,
			report.AddResultByResultEvent,
			"", config.GlobalConfig.NoInteractsh, config.GlobalEmbedPocs,
			config.GlobalConfig.NucleiTemplate, strings.Split(config.GlobalConfig.ExcludeTags, ","),
			strings.Split(config.GlobalConfig.Severities, ","))
	}

	// GoPoc引擎
	gologger.Info().Msg(strconv.Itoa(len(nucleiResults)))
}
