package httpxscan

import (
	"Findyou.WorkFlow/common/db/mysqldb"
	"Findyou.WorkFlow/common/workflowstruct"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
	"strings"
)

func Httpxscan(targets []string, appconfig *workflowstruct.Appconfig) {
	gologger.Info().Msgf("获取到ALIVESCAN任务数量 [%d] 个", len(targets))
	taskstruct, err := mysqldb.GetTasks(strings.Join(targets, ","))
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	err = mysqldb.ProcessTasks(taskstruct, "Processing")
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	//禁用标准输入DisableStdin，导致程序一直卡死
	options := runner.Options{
		Methods:                   "GET",
		InputTargetHost:           targets,
		Favicon:                   true,
		Hashes:                    "md5",
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
			// handle error
			if resp.Err != nil {
				gologger.Error().Msgf("%s: %s\n", resp.Input, resp.Err)
				//查找target
				target, err := mysqldb.GetTargetID(resp.URL)
				if err != nil {
					gologger.Error().Msg(err.Error())
				}
				// 如果失败，设置状态为失败
				err = mysqldb.ProcessTargets(target, resp.Title, "失败")
				if err != nil {
					gologger.Error().Msgf("Failed to process target: %s", err.Error())
				}
				return
			}
			gologger.Info().Msgf("[HTTPX] [%d] %s [%s]\n", resp.StatusCode, resp.URL, resp.Title)
			//查找target
			target, err := mysqldb.GetTargetID(resp.URL)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				err = mysqldb.ProcessTargets(target, resp.Title, "存活")
			} else {
				err = mysqldb.ProcessTargets(target, resp.Title, "非正常状态码")
			}
			if err != nil {
				gologger.Error().Msgf("Failed to process target: %s", err.Error())
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
	gologger.AuditTimeLogger("响应探测结束")
}
