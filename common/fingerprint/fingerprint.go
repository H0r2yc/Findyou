package fingerprint

import (
	"Findyou/common/callback"
	"Findyou/common/config"
	"Findyou/common/db"
	"Findyou/common/httpxscan"
	"Findyou/common/output"
	"Findyou/common/utils"
	_ "embed"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"net/url"
	"runtime"
	"strconv"
	"sync"
)

func Fingerprint(appconfig *config.Appconfig) {
	targets, err := db.GetAllTargets(1)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	if len(targets) == 0 {
		return
	}
	var aLiveURLs []string
	for _, target := range targets {
		aLiveURLs = append(aLiveURLs, target.Target)
	}
	// 前置任务目录爆破
	if appconfig.Fingerprint.IsDirsearch {
		//TODO 现在放到一个checkURLs中，后面放到redis并使用分布式获取任务扫描
		var checkURLs []string
		for _, u := range aLiveURLs {
			for path, _ := range config.Dirs {
				Url := ""
				if u[len(u)-1:] == "/" && path[0:1] == "/" {
					Url = u[:len(u)-1] + path
				} else {
					Url = u + path
				}
				checkURLs = append(checkURLs, Url)
			}
			subdomain, err2 := config.GetFirstSubdomain(u)
			if err2 != nil {
				//gologger.Error().Msg(err2.Error())
				continue
			}
			//添加子域名作为目录
			Url := ""
			if u[len(u)-1:] == "/" {
				Url = u + subdomain
			} else {
				Url = u + "/" + subdomain
			}
			checkURLs = append(checkURLs, Url)
		}
		checkURLs = utils.RemoveDuplicateElement(checkURLs)
		gologger.Info().Msg("开始主动指纹探测")
		//TODO 放入redis分布式处理
		httpxscan.DirBrute(checkURLs, appconfig, callback.DirBruteCallBack)
	}
	//指纹识别
	FingerprintIdentification()
}

func FingerprintIdentification() {
	gologger.Info().Msg("指纹识别中")

	for rootURL, urlEntity := range config.GlobalURLMap {
		banner := ""
		if urlEntity.IP != "" {
			hostPort := fmt.Sprintf("%s:%d", urlEntity.IP, urlEntity.Port)

			bodyBytes, ok := config.GlobalBannerHMap.Get(hostPort)
			if !ok {
				banner = ""
			} else {
				banner = string(bodyBytes)
			}
		}

		URL, _ := url.Parse(rootURL)

		for path, pathEntity := range urlEntity.WebPaths {
			results := checkPath(path, pathEntity, urlEntity.Port, URL.Scheme, banner, urlEntity.Cert)
			fullURL := rootURL + path

			if len(results) > 0 {
				config.GlobalResultMap[fullURL] = results
				output.FormatOutput(output.OutputMessage{
					Type:     "Finger",
					IP:       "",
					IPs:      nil,
					Port:     "",
					Protocol: "",
					Web: output.WebInfo{
						Status: strconv.Itoa(pathEntity.StatusCode),
						Title:  pathEntity.Title,
					},
					Finger:        results,
					Domain:        "",
					GoPoc:         output.GoPocsResultType{},
					URI:           fullURL,
					AdditionalMsg: "",
				})
			} else {
				config.GlobalResultMap[fullURL] = []string{}
			}
		}
	}
	gologger.AuditTimeLogger("指纹识别结束")
}

func checkPath(Path string,
	webPath config.UrlPathEntity,
	Port int, // 所开放的端口
	Protocol string, // 协议
	Banner string, // 响应
	Cert string, // TLS证书
) []string {
	var fingerPrintResults []string

	isWeb := Path != "no#web" && webPath.Hash != ""

	hashString := webPath.Hash
	body := ""
	bodyBytes, ok := config.GlobalHttpBodyHMap.Get(hashString)
	if !ok {
		body = ""
	} else {
		body = string(bodyBytes)
	}

	headerString := ""
	headerBytes, ok := config.GlobalHttpHeaderHMap.Get(webPath.HeaderHashString)
	if !ok {
		headerString = ""
	} else {
		headerString = string(headerBytes)
	}

	workers := runtime.NumCPU() * 2
	inputChan := make(chan config.FingerPEntity, len(config.Fingerprints))
	defer close(inputChan)
	results := make(chan string, len(config.Fingerprints))
	defer close(results)

	var wg sync.WaitGroup

	//接收结果
	go func() {
		for found := range results {
			if found != "" {
				fingerPrintResults = append(fingerPrintResults, found)
			}
			wg.Done()
		}
	}()

	//多线程扫描
	for i := 0; i < workers; i++ {
		go func() {
			for finger := range inputChan {
				rules := finger.Rule
				product := finger.ProductName
				expr := finger.AllString

				for _, singleRule := range rules {
					singleRuleResult := false
					if singleRule.Key == "header" {
						if isWeb && utils.DataCheckString(singleRule.Op, headerString, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "body" {
						if isWeb && utils.DataCheckString(singleRule.Op, body, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "server" {
						if isWeb && utils.DataCheckString(singleRule.Op, webPath.Server, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "title" {
						if isWeb && utils.DataCheckString(singleRule.Op, webPath.Title, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "cert" {
						if utils.DataCheckString(singleRule.Op, Cert, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "port" {
						value, err := strconv.Atoi(singleRule.Value)
						if err == nil && utils.DataCheckInt(singleRule.Op, Port, value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "protocol" {
						if singleRule.Op == 0 {
							if Protocol == singleRule.Value {
								singleRuleResult = true
							}
						} else if singleRule.Op == 1 {
							if Protocol != singleRule.Value {
								singleRuleResult = true
							}
						}
					} else if singleRule.Key == "path" {
						if isWeb && utils.DataCheckString(singleRule.Op, Path, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "body_hash" {

						if isWeb && utils.DataCheckString(singleRule.Op, webPath.Hash, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "icon_hash" {
						value, err := strconv.Atoi(singleRule.Value)
						hashIcon, errHash := strconv.Atoi(webPath.IconHash)
						if isWeb && err == nil && errHash == nil && utils.DataCheckInt(singleRule.Op, hashIcon, value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "status" {
						value, err := strconv.Atoi(singleRule.Value)
						if isWeb && err == nil && utils.DataCheckInt(singleRule.Op, webPath.StatusCode, value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "content_type" {
						if isWeb && utils.DataCheckString(singleRule.Op, webPath.ContentType, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "banner" {
						if utils.DataCheckString(singleRule.Op, Banner, singleRule.Value) {
							singleRuleResult = true
						}
					} else if singleRule.Key == "type" {
						if singleRule.Value == "service" {
							singleRuleResult = true
						}
					}
					if singleRuleResult {
						expr = expr[:singleRule.Start] + "T" + expr[singleRule.End:]
					} else {
						expr = expr[:singleRule.Start] + "F" + expr[singleRule.End:]
					}
				}

				r := utils.BoolEval(expr)
				if r {
					results <- product
				} else {
					results <- ""
				}

			}

		}()
	}

	//添加扫描目标
	for _, input := range config.Fingerprints {
		wg.Add(1)
		inputChan <- input
	}
	wg.Wait()

	return utils.RemoveDuplicateElement(fingerPrintResults)
}
