package httpxscan

import (
	"Findyou.WorkFlow/common/db/mysqldb"
	"Findyou.WorkFlow/common/fingerprint"
	"Findyou.WorkFlow/common/workflowstruct"
	"bytes"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io/ioutil"
	"strings"
	"unicode/utf8"
)

func Httpxscan(targets []string, appconfig *workflowstruct.Appconfig) {
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
	//禁用标准输入DisableStdin，导致程序一直卡死
	//ResponseInStdout是返回body和header的
	options := runner.Options{
		Methods:                   "GET",
		InputTargetHost:           targets,
		Favicon:                   true,
		Hashes:                    "md5",
		ResponseInStdout:          true,
		OutputServerHeader:        true,
		TLSProbe:                  true,
		FollowHostRedirects:       true,
		MaxResponseBodySizeToRead: 1048576,
		MaxRedirects:              5,
		ExtractTitle:              true,
		DisableStdin:              true,
		Timeout:                   appconfig.Httpxconfig.WebTimeout,
		Retries:                   2,
		HTTPProxy:                 appconfig.Httpxconfig.HTTPProxy,
		NoFallbackScheme:          true,
		RandomAgent:               true,
		Threads:                   appconfig.Httpxconfig.WebThreads,
		OnResult: func(resp runner.Result) {
			// 检查 Title 是否为有效的 UTF-8 字符串
			if !utf8.ValidString(resp.Title) {
				reader := transform.NewReader(bytes.NewReader([]byte(resp.Title)), simplifiedchinese.GBK.NewDecoder())
				utf8Data, err := ioutil.ReadAll(reader)
				if err != nil {
					gologger.Error().Msg(err.Error())
				}
				resp.Title = string(utf8Data)
			}
			if !utf8.ValidString(resp.Title) {
				resp.Title = "未知编码的标题"
			}
			// handle error
			if resp.Err != nil {
				gologger.Info().Msgf("请求错误: %s: %s\n", resp.Input, resp.Err)
				//查找target
				target, err := mysqldb.GetTargetID(resp.URL)
				if err != nil {
					gologger.Error().Msg(err.Error())
				}
				//如果找不到target,通过input在搜索一次
				if target.ID == 0 {
					target, err = mysqldb.GetTargetID(resp.Input)
					if err != nil {
						gologger.Error().Msg(err.Error())
					}
				}
				// 如果失败，设置状态为失败
				err = mysqldb.ProcessTargets(target, resp.Title, "失败", "", 0)
				if err != nil {
					gologger.Error().Msgf("Failed to process target: %s,inputurl: %s", err.Error(), resp.Input)
				}
				return
			}
			//检测敏感信息
			bodydata := fingerprint.FindInBody(resp.ResponseBody)
			if bodydata.ICP != "" || bodydata.Supplychain != "" || bodydata.PhoneNum != "" {
				err = mysqldb.SensitiveInfoToDB(resp.URL, bodydata.PhoneNum, bodydata.Supplychain, bodydata.ICP)
				gologger.Info().Msgf("[INFOFIND] %s [%s] [%s] [%s]\n", resp.URL, bodydata.ICP, bodydata.PhoneNum, bodydata.Supplychain)
			}
			//查找target
			target, err := mysqldb.GetTargetID(resp.URL)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			//如果找不到target,通过input在搜索一次
			if target.ID == 0 {
				target, err = mysqldb.GetTargetID(resp.Input)
				if err != nil {
					gologger.Error().Msg(err.Error())
				}
			}
			//被动检测指纹
			finger, priority, matched := fingerprint.Fingerprint(resp)
			if matched {
				gologger.Info().Msgf("[Finger] %s [%s] 等级：%d\n", resp.URL, finger, priority)
				if priority > 1 {
					highleveltarget := mysqldb.HighLevelTargets{
						Url:       resp.URL,
						Title:     resp.Title,
						Finger:    finger,
						Priority:  uint(priority),
						CompanyID: 0,
					}
					highlevellist = append(highlevellist, highleveltarget)
				}
			} else {
				gologger.Info().Msgf("[HTTPX] [%d] %s [%s]\n", resp.StatusCode, resp.URL, resp.Title)
			}
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				err = mysqldb.ProcessTargets(target, resp.Title, "存活", finger, priority)
			} else {
				err = mysqldb.ProcessTargets(target, resp.Title, "非正常状态码", finger, priority)
			}
			if err != nil {
				gologger.Error().Msgf("Failed to process target: %s,inputurl: %s", err.Error(), resp.Input)
			}
		},
	}

	if err := options.ValidateOptions(); err != nil {
		gologger.Error().Msgf("httpx参数错误")
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		gologger.Error().Msgf("runner.New(&options) error")
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()
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
	gologger.AuditTimeLogger("响应探测结束")
}
