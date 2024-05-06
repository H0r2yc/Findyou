package httpxscan

import (
	"Findyou/common/config"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
)

func DirBrute(urls []string, appconfig *config.Appconfig, callBack func(resp runner.Result)) {
	options := runner.Options{
		Methods:                   "GET",
		InputTargetHost:           urls,
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
		// 是否为目录爆破，如果是目录爆破默认不存响应
		//IsBrute:                   true,
	}

	if err := options.ValidateOptions(); err != nil {
		gologger.Error().Msgf("params error")
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		gologger.Error().Msgf("runner.New(&options) error")
	}
	httpxRunner.CallBack = callBack
	httpxRunner.RunEnumeration()
	httpxRunner.Close()
}
