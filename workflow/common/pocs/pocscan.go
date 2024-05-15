package pocs

import (
	"Findyou.WorkFlow/common/callnuclei"
	"Findyou.WorkFlow/common/report"
	"Findyou.WorkFlow/common/workflowstruct"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"strconv"
	"strings"
)

func PocScan() {
	// 调用Nuclei
	var nucleiResults []output.ResultEvent
	TargetAndPocsName, count := GetPocs(workflowstruct.WorkFlowDB)
	if count > 0 {
		nucleiResults = callnuclei.CallNuclei(TargetAndPocsName,
			workflowstruct.GlobalConfig.HTTPProxy,
			report.AddResultByResultEvent,
			"", workflowstruct.GlobalConfig.NoInteractsh, workflowstruct.GlobalEmbedPocs,
			workflowstruct.GlobalConfig.NucleiTemplate, strings.Split(workflowstruct.GlobalConfig.ExcludeTags, ","),
			strings.Split(workflowstruct.GlobalConfig.Severities, ","))
	}

	// GoPoc引擎
	gologger.Info().Msg(strconv.Itoa(len(nucleiResults)))
}
