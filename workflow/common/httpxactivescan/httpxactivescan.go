package httpxactivescan

import (
	"Findyou.WorkFlow/common/workflowstruct"
	"bytes"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io/ioutil"
	"unicode/utf8"
)

func HttpxActiveScan(protocol, bodydata string, url []string, headers map[string]string) workflowstruct.Urlentity {
	var urlentity workflowstruct.Urlentity
	options := runner.Options{
		Methods:                   protocol,
		InputTargetHost:           url,
		CustomHeaders:             headers,
		RequestBody:               bodydata,
		Favicon:                   true,
		Hashes:                    "md5",
		ResponseInStdout:          true,
		OutputServerHeader:        true,
		TLSProbe:                  false,
		FollowHostRedirects:       true,
		MaxResponseBodySizeToRead: 1048576,
		MaxRedirects:              5,
		ExtractTitle:              true,
		DisableStdin:              true,
		Timeout:                   10,
		Retries:                   2,
		HTTPProxy:                 "",
		NoFallbackScheme:          true,
		RandomAgent:               true,
		Threads:                   100,
		OnResult: func(resp runner.Result) {
			// handle error
			if resp.Err != nil {
				gologger.Info().Msgf("请求错误: %s: %s\n", resp.Input, resp.Err)
				urlentity.Url = resp.URL
				urlentity.InputUrl = resp.Input
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
			gologger.Info().Msgf("[HTTPX-ACTIVE] [%d] %s [%s]\n", urlentity.StatusCode, urlentity.Url, urlentity.Title)
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
	return urlentity
}
