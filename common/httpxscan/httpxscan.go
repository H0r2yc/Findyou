package httpxscan

import (
	"Findyou/common/config"
	"Findyou/common/db"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
)

func Httpxscan(appconfig *config.Appconfig) {
	targets, err := db.GetAllTargets(0)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	if len(targets) == 0 {
		return
	}
	gologger.Info().Msg("存活探测中")
	var targetlist []string
	for _, target := range targets {
		targetlist = append(targetlist, target.Target)
	}
	options := runner.Options{
		Methods:                   "GET",
		InputTargetHost:           targetlist,
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
				target, err := db.GetTargetID(targets, r.URL)
				if err != nil {
					gologger.Error().Msg(err.Error())
				}
				// 如果失败，设置为2
				err = db.ProcessTargets(target, r.Title, 2)
				if err != nil {
					gologger.Error().Msgf("Failed to process target: %s", err.Error())
				}
				return
			}
			gologger.Silent().Msgf("[HTTPX] [%d] %s [%s]\n", r.StatusCode, r.URL, r.Title)
			//查找target
			target, err := db.GetTargetID(targets, r.URL)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			err = db.ProcessTargets(target, r.Title, 1)
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
	gologger.AuditTimeLogger("响应探测结束")
}
