package httpxscan

import (
	"Findyou.WorkFlow/common/workflowstruct"
	"bytes"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io/ioutil"
	"unicode/utf8"
)

// 目前ACN采取的方式是每次将ACN列表去重入库
func Httpxscan(targets []string, WebTimeout, WebThreads int, HTTPProxy string) ([]workflowstruct.Urlentity, []string) {
	var urlentities []workflowstruct.Urlentity
	var ancnlist []string
	//禁用标准输入DisableStdin，导致程序一直卡死
	//ResponseInStdout是返回body和header的
	options := runner.Options{
		Methods:                   "GET",
		InputTargetHost:           targets,
		Favicon:                   true,
		Hashes:                    "md5",
		ResponseInStdout:          true,
		OutputServerHeader:        true,
		TLSProbe:                  false,
		FollowHostRedirects:       true,
		MaxResponseBodySizeToRead: 1048576,
		MaxRedirects:              2,
		ExtractTitle:              true,
		DisableStdin:              true,
		Timeout:                   WebTimeout,
		//Retries:                   2,
		HTTPProxy:        HTTPProxy,
		NoFallbackScheme: true,
		RandomAgent:      true,
		Threads:          WebThreads,
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
			urlentity.ContentLength = resp.ContentLength
			urlentities = append(urlentities, urlentity)
			ancnlist = append(ancnlist, resp.ACN...)
			for _, ancn := range ancnlist {
				fmt.Printf("从%s获取到ancn:%s", resp.URL, ancn)
			}
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
	return urlentities, ancnlist
}
