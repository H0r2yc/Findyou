package httpxscan

import (
	"Findyou.WorkFlow/common/output"
	"Findyou.WorkFlow/common/utils"
	"Findyou.WorkFlow/common/workflowstruct"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
	"strconv"
	"strings"
)

func DirBrute(urls []string, appconfig *workflowstruct.Appconfig) {
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
		//IsBrute:                   true,
		OnResult: func(resp runner.Result) {
			var Paths []string
			for dbPath, _ := range workflowstruct.Dirs {
				if strings.HasSuffix(resp.Path, dbPath) {
					Paths = append(Paths, dbPath)
				}
			}

			for _, path := range Paths {
				productNames := workflowstruct.Dirs[path]
				for _, productName := range productNames {
					success := false
					for _, v := range workflowstruct.Fingerprints {
						if success {
							break
						}
						if v.ProductName == productName {
							portInt, err := strconv.Atoi(resp.Port)
							if err != nil {
								portInt = -1
							}
							r := utils.SingleCheck(v, resp.Scheme, resp.Header, resp.Body, resp.WebServer, resp.Title, utils.GetTLSString(resp),
								portInt, resp.Path, "0", "0", resp.StatusCode, resp.ContentType, "")
							// 满足这个products的要求
							if r {
								success = true
								// 给对应的urlEntry添加指纹
								Url := utils.URLParse(resp.URL)
								rootURL := fmt.Sprintf("%s://%s", Url.Scheme, Url.Host)

								workflowstruct.GlobalURLMapLock.Lock()
								_, rootURLOk := workflowstruct.GlobalURLMap[rootURL]
								workflowstruct.GlobalURLMapLock.Unlock()
								if rootURLOk {
									// 如果爆破来源上一步验活，那这里必然存在rootURL.
									// 有这个root，查看这个path，如果没这个path再加
									workflowstruct.GlobalURLMapLock.Lock()
									_, pathOK := workflowstruct.GlobalURLMap[rootURL].WebPaths[Url.Path]
									workflowstruct.GlobalURLMapLock.Unlock()
									if !pathOK {
										// 没有这个path
										md5 := resp.Hashes["body_md5"].(string)
										headerMd5 := resp.Hashes["header_md5"].(string)
										_ = workflowstruct.GlobalHttpBodyHMap.Set(md5, []byte(resp.Body))
										_ = workflowstruct.GlobalHttpHeaderHMap.Set(headerMd5, []byte(resp.Header))
										workflowstruct.GlobalURLMapLock.Lock()
										workflowstruct.GlobalURLMap[rootURL].WebPaths[Url.Path] = workflowstruct.UrlPathEntity{
											Hash:             md5,
											Title:            resp.Title,
											StatusCode:       resp.StatusCode,
											ContentType:      resp.ContentType,
											Server:           resp.WebServer,
											ContentLength:    resp.ContentLength,
											HeaderHashString: headerMd5,
											IconHash:         resp.FavIconMMH3,
										}
										workflowstruct.GlobalURLMapLock.Unlock()
									}

									output.FormatOutput(output.OutputMessage{
										Type:          "Active-Finger",
										IP:            "",
										IPs:           nil,
										Port:          "",
										Protocol:      "",
										Web:           output.WebInfo{},
										Finger:        []string{productName},
										Domain:        "",
										GoPoc:         output.GoPocsResultType{},
										URI:           resp.URL,
										AdditionalMsg: "",
									})
									// gologger.Silent().Msgf("[Active-Finger] %s [%s]", resp.URL, productName)
								}
							}
						}
					}
				}
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
	//httpxRunner.CallBack = callBack
	httpxRunner.RunEnumeration()
	httpxRunner.Close()
}
