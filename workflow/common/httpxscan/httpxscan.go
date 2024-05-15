package httpxscan

import (
	"Findyou.WorkFlow/common/db/mysqldb"
	"Findyou.WorkFlow/common/workflowstruct"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
	"strings"
)

func Httpxscan(targets []string, appconfig *workflowstruct.Appconfig) {
	gologger.Info().Msgf("存活探测任务启动， [%d] 个目标探测中", len(targets))
	taskstruct, err := mysqldb.GetTasks(strings.Join(targets, ","))
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	err = mysqldb.ProcessTasks(taskstruct, "Processing")
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	options := runner.Options{
		Methods:                   "GET",
		InputTargetHost:           targets,
		Favicon:                   true,
		Hashes:                    "md5",
		OutputServerHeader:        true,
		TLSProbe:                  true,
		MaxResponseBodySizeToRead: 1048576,
		FollowHostRedirects:       true,
		MaxRedirects:              5,
		ExtractTitle:              true,
		Timeout:                   appconfig.Httpxconfig.WebTimeout,
		Retries:                   2,
		HTTPProxy:                 appconfig.Httpxconfig.HTTPProxy,
		NoFallbackScheme:          true,
		RandomAgent:               true,
		Threads:                   appconfig.Httpxconfig.WebThreads,
		OnResult: func(r runner.Result) {
			// handle error
			if r.Err != nil {
				gologger.Error().Msgf("%s: %s\n", r.Input, r.Err)
				//查找target
				target, err := mysqldb.GetTargetID(r.URL)
				if err != nil {
					gologger.Error().Msg(err.Error())
				}
				// 如果失败，设置状态为失败
				err = mysqldb.ProcessTargets(target, r.Title, "失败")
				if err != nil {
					gologger.Error().Msgf("Failed to process target: %s", err.Error())
				}
				return
			}
			gologger.Silent().Msgf("[HTTPX] [%d] %s [%s]\n", r.StatusCode, r.URL, r.Title)
			//查找target
			target, err := mysqldb.GetTargetID(r.URL)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			if r.StatusCode >= 200 && r.StatusCode < 500 {
				err = mysqldb.ProcessTargets(target, r.Title, "存活")
			} else {
				err = mysqldb.ProcessTargets(target, r.Title, "非正常状态码")
			}
			if err != nil {
				gologger.Error().Msgf("Failed to process target: %s", err.Error())
			}
		},
	}

	if err := options.ValidateOptions(); err != nil {
		gologger.Error().Msgf("params error")
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
