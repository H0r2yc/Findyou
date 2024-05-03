package onlineengine

import (
	"Findyou/common/cdn"
	"Findyou/common/config"
	"Findyou/common/db"
	"Findyou/common/output"
	"Findyou/common/utils"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	"io"
	"net/http"
	"strings"
	"time"
)

type FOFAResponseJson struct {
	Error   bool       `json:"error"`
	Mode    string     `json:"mode"`
	Page    int        `json:"page"`
	Query   string     `json:"query"`
	Results [][]string `json:"results"`
	Size    int        `json:"size"`
}

var nildbdatas = db.DBdata{}

func FOFASearch(targetlist *config.Targetconfig, fofakey string, cdnthread int) {
	searchkeywords := FofaMakeKeyword(targetlist)
	gologger.Info().Msgf("准备从fofa获取数据")
	for _, keyword := range searchkeywords {
		result := SearchFOFACore(keyword, fofakey, 9000, cdnthread)
		err := targetsToDB(result)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		err = IpsToDB(result)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		err = DomainsToDB(result)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}
}

func FOFADBSearch(datalist, globalkeywords []string, fofakey, datatype string, cdnthread int) {
	gologger.Info().Msg("联想收集...")
	searchkeywords := DBMakeKeyword(datalist, globalkeywords, datatype)
	gologger.Info().Msgf("准备从fofa获取数据")
	for _, keyword := range searchkeywords {
		result := SearchFOFACore(keyword, fofakey, 9000, cdnthread)
		err := targetsToDB(result)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		err = IpsToDB(result)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		err = DomainsToDB(result)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}
}

// 从Fofa中搜索目标
func SearchFOFACore(keyword, fofakey string, pageSize, cdnthread int) config.Targets {
	targets := config.Targets{}
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)
	config.GlobalIPDomainMap = make(map[string][]string)
	url := "https://fofa.info/api/v1/search/all"
	if !strings.Contains(fofakey, ":") {
		gologger.Fatal().Msg("请核对FOFA API KEY格式。正确格式为: email:key")
	}
	tmp := strings.Split(fofakey, ":")
	email := tmp[0]
	key := tmp[1]
	req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		gologger.Fatal().Msgf("FOFA API请求构建失败。")
	}
	unc := keyword
	search := base64.StdEncoding.EncodeToString([]byte(unc))
	q := req.URL.Query()
	q.Add("qbase64", search)
	q.Add("email", email)
	q.Add("key", key)
	q.Add("page", "1")
	q.Add("size", fmt.Sprintf("%d", pageSize))
	q.Add("fields", "host,protocol,title,icp,ip,port,domain")
	q.Add("full", "false")
	req.URL.RawQuery = q.Encode()

	// 确保不会超速
	time.Sleep(time.Second * 3)

	resp, errDo := client.Do(req)
	if errDo != nil {
		gologger.Error().Msgf("[Fofa] [%s] 资产查询失败！请检查网络状态。Error:%s", keyword, errDo.Error())
		return targets
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Error().Msgf("[Fofa] 获取Fofa 响应Body失败: %v", err.Error())
		return targets
	}

	var responseJson FOFAResponseJson
	if err = json.Unmarshal(data, &responseJson); err != nil {
		gologger.Error().Msgf("[Fofa] 返回数据Json解析失败! Error:%s", err.Error())
		return targets
	}

	if responseJson.Error {
		gologger.Error().Msgf("[Fofa] [%s] 搜索失败！返回响应体Error为True。返回信息: %v", keyword, string(data))
		return targets
	}

	if responseJson.Size == 0 {
		gologger.Error().Msgf("[Fofa] [%s] 无结果。", keyword)
		return targets
	}
	gologger.Info().Msgf("[Fofa] [%s] 已查询: %d/%d", keyword, len(responseJson.Results), responseJson.Size)
	// 做一个域名缓存，避免重复dns请求
	domainCDNMap := make(map[string]bool)
	for _, result := range responseJson.Results {
		host := result[0]
		protocol := result[1]
		port := result[5]
		domain := ""
		if result[6] != "" {
			//这里添加的域名host直接到target只是一个端口，实际可能存在其他端口
			if strings.Contains(host, "://") {
				targets.Targets = append(targets.Targets, host)
			} else {
				targets.Targets = append(targets.Targets, protocol+"://"+host)
			}
			realHost := strings.ReplaceAll(host, protocol+"://", "")
			domain = strings.ReplaceAll(realHost, ":"+port, "")
		} else {
			if strings.Contains(host, "://") {
				targets.Targets = append(targets.Targets, host)
			} else {
				targets.Targets = append(targets.Targets, protocol+"://"+host)
			}
			if !strings.Contains(keyword, "ip=") {
				if !db.Isipclr(result[4]) {
					targets.IPs = append(targets.IPs, result[4])
				}
			}
		}
		if domain != "" {
			targets.Domains = append(targets.Domains, domain)
		}
	}

	targets.Domains = utils.RemoveDuplicateElement(targets.Domains)
	isCDN := false
	//如果语法是ip扫描，就不探测cdn了，而且ip也不会进入到ips库中继续等待扫描，因为使用的语法是/24，重复扫描
	if !strings.Contains(keyword, "ip=") && len(targets.Domains) != 0 {
		var icp, title, protocol, ip, port, host, domain string
		gologger.Info().Msgf("正在查询 [%v] 个域名是否为CDN资产", len(targets.Domains))
		cdnDomains, normalDomains, _ := cdn.CheckCDNs(targets.Domains, cdnthread)
		for _, d := range cdnDomains {
			_, ok := domainCDNMap[d]
			if !ok {
				domainCDNMap[d] = true
			}
		}
		for _, d := range normalDomains {
			_, ok := domainCDNMap[d]
			if !ok {
				domainCDNMap[d] = false
			}
		}
		for _, result := range responseJson.Results {
			host = result[0]
			protocol = result[1]
			icp = result[2]
			title = result[3]
			ip = result[4]
			port = result[5]
			domain = ""
			if result[6] != "" {
				realHost := strings.ReplaceAll(host, protocol+"://", "")
				domain = strings.ReplaceAll(realHost, ":"+port, "")
			}
			if domain != "" {
				domainInfo, ok := domainCDNMap[domain]
				if ok {
					isCDN = domainInfo
				}
				if !isCDN {
					//targets.DomainIPMap[domain] = ip
					AddIPDomainMap(targets, ip, domain)
				}

			}
			//Todo 比如通过cert或者其他方式能不能正常获取到ip并添加到数据库
			if !isCDN {
				//什么情况下把ip放入数据库，/24情况下如果C段的进去数据库会一直反复，还得改
			}
		}

		show := "[Fofa]"
		addTarget := ""
		if config.GlobalConfig.OnlyIPPort && !isCDN {
			if protocol == "http" || protocol == "https" {
				addTarget = protocol + "://" + ip + ":" + port
				show += " " + addTarget
			} else {
				addTarget = protocol + "://" + ip + ":" + port
				show += " " + addTarget
			}
		} else {
			if protocol == "http" {
				addTarget = protocol + "://" + host
				show += " " + addTarget
			} else if protocol == "https" {
				addTarget = host
				show += " " + host
			} else {
				addTarget = host
				show += " " + protocol + "://" + host
			}
		}

		if title != "" {
			show += " [" + title + "]"
		}
		if icp != "" {
			icp += " [" + icp + "]"
		}
		if isCDN {
			show += " [CDN]"
		}

		if utils.GetItemInArray(targets.Targets, addTarget) == -1 {
			if !isCDN || config.GlobalConfig.AllowCDNAssets {
				targets.Targets = append(targets.Targets, addTarget)
			}
			// gologger.Silent().Msg(show)
			output.FormatOutput(output.OutputMessage{
				Type:          "Fofa",
				IP:            ip,
				IPs:           nil,
				Port:          port,
				Protocol:      protocol,
				Web:           output.WebInfo{},
				Finger:        nil,
				Domain:        domain,
				GoPoc:         output.GoPocsResultType{},
				URI:           host,
				City:          "",
				Show:          show,
				AdditionalMsg: "",
			})
		}

	}
	targets.Targets = utils.RemoveDuplicateElement(targets.Targets)
	targets.IPs = utils.RemoveDuplicateElement(targets.IPs)
	return targets
}
