package httpxscan

import (
	"Findyou.WorkFlow/common/db/mysqldb"
	"Findyou.WorkFlow/common/fingerprint"
	"Findyou.WorkFlow/common/utils"
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
	var urlentities []workflowstruct.Urlentity
	var ancnlist []string
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
			var urlentity workflowstruct.Urlentity
			// handle error
			if resp.Err != nil {
				gologger.Info().Msgf("请求错误: %s: %s\n", resp.Input, resp.Err)
				urlentity.Url = resp.URL
				urlentity.InputUrl = resp.Input
				urlentities = append(urlentities, urlentity)
				return
			}
			// 检查 Title 是否为有效的 UTF-8 字符串
			if !utf8.ValidString(resp.Title) {
				reader := transform.NewReader(bytes.NewReader([]byte(resp.Title)), simplifiedchinese.GBK.NewDecoder())
				utf8Data, err := ioutil.ReadAll(reader)
				if err != nil {
					gologger.Error().Msg(err.Error())
				}
				resp.Title = string(utf8Data)
			}
			urlentity.Url = resp.URL
			urlentity.InputUrl = resp.Input
			urlentity.Status = true
			urlentity.Title = resp.Title
			urlentity.Header = resp.ResponseHeaders
			urlentity.Body = resp.ResponseBody
			urlentity.Iconhash_md5 = resp.IconhashMd5
			urlentity.Iconhash_mmh3 = resp.FavIconMMH3
			urlentity.StatusCode = resp.StatusCode
			urlentities = append(urlentities, urlentity)
			ancnlist = append(ancnlist, resp.ACN...)
			gologger.Info().Msgf("[HTTPX] [%d] %s [%s]\n", urlentity.StatusCode, urlentity.Url, urlentity.Title)
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
	//下面是被动信息收集和指纹识别,以及acn入库targets
	ancnlist = utils.RemoveDuplicateElement(ancnlist)
	err = mysqldb.TargetsToDB(ancnlist, 999, taskstruct.ID)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	gologger.Info().Msg("开始信息收集和指纹检测")
	for _, urlentity := range urlentities {
		//查找target
		target, err := mysqldb.GetTargetID(urlentity.InputUrl)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		if !urlentity.Status {
			// 如果失败，设置状态为失败
			err = mysqldb.ProcessTargets(target, urlentity.Title, "失败", "", 0)
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
			err = mysqldb.ProcessTargets(target, urlentity.Title, "存活", finger, priority)
		} else {
			err = mysqldb.ProcessTargets(target, urlentity.Title, "非正常状态码", finger, priority)
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
	gologger.AuditTimeLogger("响应探测结束")
}
