package callback

import (
	"Findyou/common/config"
	"Findyou/common/output"
	"Findyou/common/utils"
	"fmt"
	"github.com/projectdiscovery/httpx/runner"
	"strconv"
	"strings"
)

func DirBruteCallBack(resp runner.Result) {
	fmt.Println(12312313)
	var Paths []string
	for dbPath, _ := range config.Dirs {
		if strings.HasSuffix(resp.Path, dbPath) {
			Paths = append(Paths, dbPath)
		}
	}

	for _, path := range Paths {
		productNames := config.Dirs[path]
		for _, productName := range productNames {
			success := false
			for _, v := range config.Fingerprints {
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

						config.GlobalURLMapLock.Lock()
						_, rootURLOk := config.GlobalURLMap[rootURL]
						config.GlobalURLMapLock.Unlock()
						if rootURLOk {
							// 如果爆破来源上一步验活，那这里必然存在rootURL.
							// 有这个root，查看这个path，如果没这个path再加
							config.GlobalURLMapLock.Lock()
							_, pathOK := config.GlobalURLMap[rootURL].WebPaths[Url.Path]
							config.GlobalURLMapLock.Unlock()
							if !pathOK {
								// 没有这个path
								md5 := resp.Hashes["body_md5"].(string)
								headerMd5 := resp.Hashes["header_md5"].(string)
								_ = config.GlobalHttpBodyHMap.Set(md5, []byte(resp.Body))
								_ = config.GlobalHttpHeaderHMap.Set(headerMd5, []byte(resp.Header))
								config.GlobalURLMapLock.Lock()
								config.GlobalURLMap[rootURL].WebPaths[Url.Path] = config.UrlPathEntity{
									Hash:             md5,
									Title:            resp.Title,
									StatusCode:       resp.StatusCode,
									ContentType:      resp.ContentType,
									Server:           resp.WebServer,
									ContentLength:    resp.ContentLength,
									HeaderHashString: headerMd5,
									IconHash:         resp.FavIconMMH3,
								}
								config.GlobalURLMapLock.Unlock()
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
}
