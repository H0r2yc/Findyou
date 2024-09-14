package aliveandpassivityscan

import (
	"Findyou.WorkFlow/common/db/mysqldb"
	"Findyou.WorkFlow/common/fingerprint"
	"Findyou.WorkFlow/common/httpxscan"
	"Findyou.WorkFlow/common/utils"
	"Findyou.WorkFlow/common/workflowstruct"
	"github.com/projectdiscovery/gologger"
	"strings"
)

func AliveAndPassivityScan(targets []string, appconfig *workflowstruct.Appconfig) {
	gologger.Info().Msgf("获取到ALIVEANDPASSIVITYSCAN任务数量 [%d] 个", len(targets))
	taskstruct, err := mysqldb.GetTasks(strings.Join(targets, ","))
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	err = mysqldb.ProcessTasks(taskstruct, "Processing")
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	//设置可能存在漏洞的url列表
	var highlevellist []mysqldb.HighLevelTargets
	urlentities, ancnlist := httpxscan.Httpxscan(targets, appconfig.Httpxconfig.WebTimeout, appconfig.Httpxconfig.WebThreads, appconfig.Httpxconfig.HTTPProxy)
	//下面是被动信息收集和指纹识别,以及acn入库targets
	ancnlist = utils.RemoveDuplicateElement(ancnlist)
	gologger.Info().Msgf("ANCN数量: %d", len(ancnlist))
	err = mysqldb.TargetsToDB(ancnlist, 999, taskstruct.ID, 0, "Waiting", "")
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	gologger.Info().Msg("开始信息收集和被动指纹检测")
	for _, urlentity := range urlentities {
		//查找target
		target, err := mysqldb.GetTargetID(urlentity.InputUrl)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		if !urlentity.Status {
			// 如果失败，设置状态为失败
			err = mysqldb.ProcessTargets(target, urlentity.Title, "失败", "", urlentity.Url, 0)
			if err != nil {
				gologger.Error().Msgf("Failed to process target: %s url: [%s]", err.Error(), urlentity.Url)
			}
			continue
		}
		//检测敏感信息
		bodydata := fingerprint.FindInBody(urlentity.Body)
		if bodydata.ICP != "" || bodydata.Supplychain != "" || bodydata.PhoneNum != "" {
			err = mysqldb.SensitiveInfoToDB(urlentity.Url, bodydata.PhoneNum, bodydata.Supplychain, bodydata.ICP)
			gologger.Info().Msgf("[INFOFIND] %s [%s] [%s] [%s]\n", urlentity.Url, bodydata.ICP, bodydata.PhoneNum, bodydata.Supplychain)
		}
		//被动检测指纹
		finger, priority, matched := fingerprint.Fingerprint(urlentity)
		if matched {
			gologger.Info().Msgf("[Finger] %s [%s] 等级：%d\n", urlentity.Url, finger, priority)
			highleveltarget := mysqldb.HighLevelTargets{
				Url:       urlentity.Url,
				Title:     urlentity.Title,
				Finger:    finger,
				Priority:  uint(priority),
				CompanyID: 0,
			}
			highlevellist = append(highlevellist, highleveltarget)
		}
		if urlentity.StatusCode >= 200 && urlentity.StatusCode < 500 {
			err = mysqldb.ProcessTargets(target, urlentity.Title, "存活", finger, urlentity.Url, priority)
		} else {
			err = mysqldb.ProcessTargets(target, urlentity.Title, "非正常状态码5xx", finger, urlentity.Url, priority)
		}
		if err != nil {
			gologger.Error().Msgf("Failed to process target: %s,inputurl: %s", err.Error(), urlentity.InputUrl)
		}
	}
	err = mysqldb.ProcessTasks(taskstruct, "Completed")
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	if len(highlevellist) != 0 {
		err = mysqldb.HighLevelTargetsToDB(highlevellist)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}
	gologger.AuditTimeLogger("存活探测结束")
}
