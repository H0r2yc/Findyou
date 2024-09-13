package onlineengine

import (
	"Findyou.WorkFlow/common/cdn"
	"Findyou.WorkFlow/common/db/mysqldb"
	"Findyou.WorkFlow/common/utils"
	"Findyou.WorkFlow/common/workflowstruct"
	"encoding/base64"
	"encoding/json"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type HunterResp struct {
	Code    int        `json:"code"`
	Data    hunterData `json:"data"`
	Message string     `json:"message"`
}

type infoArr struct {
	URL      string `json:"url"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Domain   string `json:"domain"`
	Protocol string `json:"protocol"`
	IsWeb    string `json:"is_web"`
	City     string `json:"city"`
	Company  string `json:"company"`
	Code     int    `json:"status_code"`
	Title    string `json:"web_title"`
	Country  string `json:"country"`
	Banner   string `json:"banner"`
}

type hunterData struct {
	InfoArr   []infoArr `json:"arr"`
	Total     int       `json:"total"`
	RestQuota string    `json:"rest_quota"`
}

func HunterSearch(datalist []string, appconfig *workflowstruct.Appconfig) {
	status := true
	var companyid int
	if len(datalist) == 0 {
		gologger.Info().Msg("获取到的HUNTERSearch任务为空，退出")
	}
	gologger.Info().Msgf("获取到HUNTERSearch任务数量 [%d] ", len(datalist))
	for _, data := range datalist {
		keywords := strings.SplitN(data, "Findyou", 2)
		dbtask, err := mysqldb.GetTasks(keywords[0])
		if err != nil {
			gologger.Error().Msgf("没有在数据库中找到对应的task")
		} else {
			err = mysqldb.ProcessTasks(dbtask, "Processing")
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
		}
		result := SearchHunterCore(keywords[0], appconfig.API.Hunter.Key, 100, appconfig.CDNConfig.CDNBruteForceThreads)
		//如果是99那么就添加备注信息
		if result.SearchStatus == 99 {
			err = mysqldb.ProcessTasks(dbtask, "Completed")
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			err = mysqldb.ProcessTasksNote(dbtask, "疑似CDN")
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
		}
		//如果不成功，那么将禁用当前workflow的此功能模块
		if result.SearchStatus != 1 && result.SearchStatus != 99 {
			gologger.Info().Msg("状态异常，10秒后重试中...")
			time.Sleep(10 * time.Second)
			result = SearchHunterCore(keywords[0], appconfig.API.Hunter.Key, 100, appconfig.CDNConfig.CDNBruteForceThreads)
			if result.SearchStatus != 1 && result.SearchStatus != 99 {
				gologger.Info().Msg("状态异常，10秒后重试中...")
				time.Sleep(10 * time.Second)
				result = SearchHunterCore(keywords[0], appconfig.API.Hunter.Key, 100, appconfig.CDNConfig.CDNBruteForceThreads)
				if result.SearchStatus != 1 && result.SearchStatus != 99 {
					gologger.Error().Msg("出错了，即将禁用workflow当前hunter搜索模块")
					status = false
					appconfig.Module.Fofasearch = false
					break
				}
			}
		}
		if len(keywords) > 1 {
			companyid, err = strconv.Atoi(keywords[1])
			if err != nil {
				companyid = 0
			}
		} else {
			gologger.Error().Msgf("找不到读取的companyid值，读取的内容为%s", data)
			companyid = 0
		}
		err = mysqldb.TargetsToDB(result.Targets, uint(companyid), dbtask.ID)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		err = mysqldb.IpsToDB(result.IPs, uint(companyid))
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		err = mysqldb.DomainsToDB(result.Domains, result.DomainIps, uint(companyid))
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		err = mysqldb.ProcessTasks(dbtask, "Completed")
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		err = mysqldb.ProcessTasksCount(dbtask, result.SearchCount)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}
	if !status {
		for _, data := range datalist {
			keywords := strings.SplitN(data, "Findyou", 2)
			dbtask, err := mysqldb.GetTasks(keywords[0])
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			err = mysqldb.ProcessTasks(dbtask, "Failed")
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
		}
	}
}

// 从hunter中搜索目标
func SearchHunterCore(keyword, hunterkey string, maxQueryPage, cdnthread int) workflowstruct.Targets {
	targets := workflowstruct.Targets{
		DomainIps: make(map[string][]string),
	}
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)
	url := "https://hunter.qianxin.com/openApi/search"
	if hunterkey == "" {
		gologger.Fatal().Msg("Hunter KEY为空")
		targets.SearchStatus = 5
		return targets
	}
	page := 1
	currentQueryCount := 0
	for page <= maxQueryPage {
		req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			gologger.Fatal().Msgf("Hunter API请求构建失败。")
		}
		unc := keyword
		search := base64.StdEncoding.EncodeToString([]byte(unc))
		q := req.URL.Query()
		q.Add("search", search)
		q.Add("api-key", hunterkey)
		q.Add("page", "1")
		q.Add("page_size", "10")
		q.Add("is_web", "3")
		req.URL.RawQuery = q.Encode()

		// 确保不会超速
		time.Sleep(time.Second * 5)

		resp, errDo := client.Do(req)
		if errDo != nil {
			gologger.Error().Msgf("[HUNTER] %s 资产查询失败！请检查网络状态。Error:%s", keyword, errDo.Error())
			targets.SearchStatus = 0
			time.Sleep(time.Second * 3)
			continue
		}
		defer resp.Body.Close()

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			gologger.Error().Msgf("获取HUNTER 响应Body失败: %v", err.Error())
			targets.SearchStatus = 2
			time.Sleep(time.Second * 3)
			continue
		}

		var responseJson HunterResp
		if err = json.Unmarshal(data, &responseJson); err != nil {
			gologger.Error().Msgf("[HUNTER] 返回数据Json解析失败! Error:%s", err.Error())
			targets.SearchStatus = 2
			time.Sleep(time.Second * 3)
			continue
		}

		if responseJson.Code != 200 {
			gologger.Error().Msgf("[HUNTER] %s 搜索失败！Error:%s", keyword, responseJson.Message)

			if strings.Contains(responseJson.Message, "今日免费积分已用") ||
				strings.Contains(responseJson.Message, "今日免费积分不足") {
				targets.SearchStatus = 4
				time.Sleep(time.Second * 3)
				continue
			}

			if responseJson.Message == "请求太多啦，稍后再试试" {
				targets.SearchStatus = 3
				gologger.Error().Msg("[HUNTER] 请求频率过快")
				time.Sleep(time.Second * 3)
				continue
			}
			return targets
		}
		if responseJson.Data.Total == 0 {
			gologger.Error().Msgf("[HUNTER] %s 无结果。", keyword)
			targets.SearchStatus = 1
			return targets
		}

		targets.SearchStatus = 1
		targets.SearchCount = uint(responseJson.Data.Total)
		currentQueryCount += len(responseJson.Data.InfoArr)
		gologger.Info().Msgf("[HUNTER] [%s] 已查询: %d/%d", keyword, currentQueryCount, responseJson.Data.Total)
		//如果是通过从db取出的domain然后查出的结果大于2000条，大概率是cdn等第三方网站，标记为cdn
		if strings.Contains(keyword, "(") && len(responseJson.Data.InfoArr) > 2000 {
			//99 代表可疑的搜索语句，可能不是目标单位，如果确定的话加入到target的yaml中
			targets.SearchStatus = 99
			return targets
		}
		var Domains []string
		var ips []string
		//这儿是ip和domain添加到target的逻辑，如果不是常规端口就添加整个url到target,如果是常规端口就添加ip或domain,毕竟网络空间引擎并不能实时探测网站的状态，万一协议有变化
		for _, v := range responseJson.Data.InfoArr {
			if v.Domain != "" {
				Domains = append(Domains, v.Domain)
				if v.Port == 80 || v.Port == 443 {
					targets.Targets = append(targets.Targets, v.Domain)
				} else {
					targets.Targets = append(targets.Targets, v.URL)
				}
			} else {
				ips = append(ips, v.IP)
				if v.Port == 80 || v.Port == 443 {
					targets.Targets = append(targets.Targets, v.IP)
				} else {
					targets.Targets = append(targets.Targets, v.URL)
				}
			}

		}
		Domains = utils.RemoveDuplicateElement(Domains)
		if len(Domains) != 0 {
			gologger.Info().Msgf("正在查询 [%v] 个域名是否为CDN资产", len(Domains))
			cdnDomains, normalDomains, domainips := cdn.CheckCDNs(Domains, cdnthread)
			gologger.Info().Msgf("CDN资产为 [%v] 个", len(cdnDomains))
			for _, d := range cdnDomains {
				targets.Domains = append(targets.Domains, d)
			}
			for _, d := range normalDomains {
				targets.Domains = append(targets.Domains, d)
				//如果解析失败了，那么就以0.0.0.0替代
				if domainips[d] != nil {
					targets.DomainIps[d] = domainips[d]
				} else {
					targets.DomainIps[d] = []string{"0.0.0.0"}
				}
			}
		}
		//将不是cdn的domain解析ip放入targets和ips中
		for _, domainip := range targets.DomainIps {
			targets.Targets = append(targets.Targets, domainip...)
			ips = append(ips, domainip...)
		}
		//domain已经判断过是否重复所以不用去重，targets需要去重
		targets.Targets = utils.RemoveDuplicateElement(targets.Targets)
		if ips != nil {
			ips = utils.RemoveDuplicateElement(ips)
			for _, str := range ips {
				if str != "" && utils.IsIPv4(str) && !utils.StringInSlice(utils.GetCIDR(str), targets.IPs) {
					targets.IPs = append(targets.IPs, str)
				}
			}
		}

		if currentQueryCount >= responseJson.Data.Total {
			return targets
		}
		page += 1
	}
	return targets
}
