package activefingerprint

import (
	"Findyou.WorkFlow/common/db/mysqldb"
	"Findyou.WorkFlow/common/fingerprint"
	"Findyou.WorkFlow/common/httpxscan"
	"Findyou.WorkFlow/common/workflowstruct"
	"github.com/projectdiscovery/gologger"
	"net/url"
	"strings"
)

func ActiveFingerprint(targets []string, appconfig *workflowstruct.Appconfig) {
	//主动探测指纹一律等级3
	gologger.Info().Msgf("获取到ACTIVEFINGERPRINT任务数量 [%d] 个", len(targets))
	taskstruct, err := mysqldb.GetTasks(strings.Join(targets, ","))
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	err = mysqldb.ProcessTasks(taskstruct, "Processing")
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	//定义指纹识别表的列表
	var highlevellist []mysqldb.HighLevelTargets
	//定义一个指向原url的字典
	fingerwithpath := make(map[string]string)
	//定义一个字典记录指纹信息
	fingerdicts := make(map[string][]string)
	for _, finger := range workflowstruct.ActiveFingerPrints {
		var urls []string
		if finger.Path != "/" {
			// 解析URL
			for _, target := range targets {
				parsedURL, err := url.Parse(target)
				if err != nil {
					gologger.Error().Msg(err.Error())
				}
				parsedURL.Path = ""
				urls = append(urls, parsedURL.String()+finger.Path)
				fingerwithpath[parsedURL.String()+finger.Path] = target
			}
		} else {
			urls = append(urls, targets...)
		}
		activeUrlentities := httpxscan.HttpxActiveScan(finger.RequestMethod, finger.RequestData, urls, finger.RequestHeaders)
		for _, activeUrlentity := range activeUrlentities {
			result2 := fingerprint.Matchfinger(activeUrlentity, finger)
			if result2 {
				gologger.Info().Msgf("[Finger] %s [%s] 等级：%d\n", activeUrlentity.InputUrl, finger.Name, finger.Priority)
				fingerdicts[activeUrlentity.InputUrl] = append(fingerdicts[activeUrlentity.InputUrl], finger.Name)
			}
		}
	}
	//开始写入数据，写入到高危表格以及更新target指纹数据，等级默认为3
	for fingerdict, fingerlist := range fingerdicts {
		var target *mysqldb.Targets
		var highlevelvuln *mysqldb.HighLevelTargets
		if fingerwithpath[fingerdict] == "" {
			//查找target
			target, err = mysqldb.GetTarget(fingerdict)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			highlevelvuln, err = mysqldb.GetHignLevelVuln(fingerdict)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
		} else {
			//查找target
			target, err = mysqldb.GetTarget(fingerwithpath[fingerdict])
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			highlevelvuln, err = mysqldb.GetHignLevelVuln(fingerwithpath[fingerdict])
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
		}
		if target.Url != "" {
			if target.FingerPrint == "" {
				err = mysqldb.ProcessTargetFingerprint(target, strings.Join(fingerlist, ","))
				if err != nil {
					gologger.Error().Msg(err.Error())
				}
			} else {
				err = mysqldb.ProcessTargetFingerprint(target, target.FingerPrint+","+strings.Join(fingerlist, ","))
				if err != nil {
					gologger.Error().Msg(err.Error())
				}
			}
		}
		if highlevelvuln.Url == "" {
			highleveltarget := mysqldb.HighLevelTargets{
				Url:       fingerdict,
				Title:     target.Title,
				Finger:    strings.Join(fingerlist, ","),
				Priority:  3,
				CompanyID: 0,
			}
			highlevellist = append(highlevellist, highleveltarget)
		} else {
			err = mysqldb.ProcessHighLevelVuln(highlevelvuln, highlevelvuln.Finger+","+strings.Join(fingerlist, ","))
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
		}
		//修改target状态为Comleted
		err = mysqldb.ProcessTargetStatus(target, "Comleted")
		if err != nil {
			gologger.Error().Msg(err.Error())
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
	gologger.AuditTimeLogger("主动指纹识别任务结束")
}
