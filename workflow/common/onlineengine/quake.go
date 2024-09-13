package onlineengine

import (
	"Findyou.WorkFlow/common/cdn"
	"Findyou.WorkFlow/common/db/mysqldb"
	"Findyou.WorkFlow/common/utils"
	"Findyou.WorkFlow/common/workflowstruct"
	"encoding/json"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	"golang.org/x/net/publicsuffix"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type QuakeServiceInfo struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    []struct {
		Time      time.Time `json:"time"`
		Transport string    `json:"transport"`
		Service   struct {
			HTTP struct {
				HTMLHash string `json:"html_hash"`
				Favicon  struct {
					Hash     string `json:"hash"`
					Location string `json:"location"`
					Data     string `json:"data"`
				} `json:"favicon"`
				Robots          string   `json:"robots"`
				SitemapHash     string   `json:"sitemap_hash"`
				Server          string   `json:"server"`
				Body            string   `json:"body"`
				XPoweredBy      string   `json:"x_powered_by"`
				MetaKeywords    string   `json:"meta_keywords"`
				RobotsHash      string   `json:"robots_hash"`
				Sitemap         string   `json:"sitemap"`
				Path            string   `json:"path"`
				Title           string   `json:"title"`
				Host            string   `json:"host"`
				SecurityText    string   `json:"security_text"`
				StatusCode      int      `json:"status_code"`
				ResponseHeaders string   `json:"response_headers"`
				URL             []string `json:"http_load_url"`
			} `json:"http"`
			Version  string `json:"version"`
			Name     string `json:"name"`
			Product  string `json:"product"`
			Banner   string `json:"banner"`
			Response string `json:"response"`
		} `json:"service"`
		Images     []interface{} `json:"images"`
		OsName     string        `json:"os_name"`
		Components []interface{} `json:"components"`
		Location   struct {
			DistrictCn  string    `json:"district_cn"`
			ProvinceCn  string    `json:"province_cn"`
			Gps         []float64 `json:"gps"`
			ProvinceEn  string    `json:"province_en"`
			CityEn      string    `json:"city_en"`
			CountryCode string    `json:"country_code"`
			CountryEn   string    `json:"country_en"`
			Radius      float64   `json:"radius"`
			DistrictEn  string    `json:"district_en"`
			Isp         string    `json:"isp"`
			StreetEn    string    `json:"street_en"`
			Owner       string    `json:"owner"`
			CityCn      string    `json:"city_cn"`
			CountryCn   string    `json:"country_cn"`
			StreetCn    string    `json:"street_cn"`
		} `json:"location"`
		Asn       int    `json:"asn"`
		Hostname  string `json:"hostname"`
		Org       string `json:"org"`
		OsVersion string `json:"os_version"`
		IsIpv6    bool   `json:"is_ipv6"`
		IP        string `json:"ip"`
		Port      int    `json:"port"`
	} `json:"data"`
	Meta struct {
		Total        int    `json:"total"`
		PaginationID string `json:"pagination_id"`
	} `json:"meta"`
}

func QUAKESearch(datalist []string, appconfig *workflowstruct.Appconfig) {
	status := true
	var companyid int
	if len(datalist) == 0 {
		gologger.Info().Msg("获取到的QUAKESEARCH任务为空，退出")
	}
	gologger.Info().Msgf("获取到QUAKESEARCH任务数量 [%d] ", len(datalist))
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
		result := SearchQUAKECore(keywords[0], appconfig.API.Quake.Key, 9000, appconfig.CDNConfig.CDNBruteForceThreads)
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
			result = SearchQUAKECore(keywords[0], appconfig.API.Quake.Key, 9000, appconfig.CDNConfig.CDNBruteForceThreads)
			if result.SearchStatus != 1 && result.SearchStatus != 99 {
				gologger.Info().Msg("状态异常，10秒后重试中...")
				time.Sleep(10 * time.Second)
				result = SearchQUAKECore(keywords[0], appconfig.API.Quake.Key, 9000, appconfig.CDNConfig.CDNBruteForceThreads)
				if result.SearchStatus != 1 && result.SearchStatus != 99 {
					gologger.Error().Msg("出错了，可能没有余额或者key错误，即将禁用workflow当前quake搜索模块")
					status = false
					appconfig.Module.Quakesearch = false
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

// 从Quake中搜索目标
func SearchQUAKECore(keyword, quakekey string, pageSize, cdnthread int) workflowstruct.Targets {
	targets := workflowstruct.Targets{
		DomainIps: make(map[string][]string),
	}
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)
	url := "https://quake.360.net/api/v3/search/quake_service"
	if quakekey == "" {
		gologger.Fatal().Msg("QUAKE API KEY为空")
		targets.SearchStatus = 5
		return targets
	}
	data := make(map[string]interface{})
	data["query"] = keyword
	data["start"] = "0"
	data["size"] = strconv.Itoa(pageSize)
	jsonData, _ := json.Marshal(data)
	req, err := retryablehttp.NewRequest(http.MethodPost, url, jsonData)
	if err != nil {
		gologger.Fatal().Msgf("Quake API请求构建失败。")
	}
	req.Header.Set("X-QuakeToken", quakekey)
	req.Header.Set("Content-Type", "application/json")
	time.Sleep(time.Second * 2)

	resp, errDo := client.Do(req)
	if errDo != nil {
		gologger.Error().Msgf("[Quake] [%s] 资产查询失败！请检查网络状态。Error:%s", keyword, errDo.Error())
		targets.SearchStatus = 0
		return targets
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		gologger.Fatal().Msgf("[Quake] API-KEY错误。请检查。")
		targets.SearchStatus = 2
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Error().Msgf("[Quake] 获取Quake 响应Body失败: %v", err.Error())
		targets.SearchStatus = 3
		return targets
	}

	var quakerespdata QuakeServiceInfo
	err = json.Unmarshal(respBody, &quakerespdata)
	if err != nil {
		gologger.Error().Msg("[Quake] 响应解析失败，疑似Token失效、。Quake接口具体返回信息如下：")
		targets.SearchStatus = 4
		gologger.Info().Msg(string(respBody))
		return targets
	}

	targets.SearchStatus = 1
	targets.SearchCount = uint(len(quakerespdata.Data))
	//如果是通过从db取出的domain然后查出的结果大于2000条，大概率是cdn等第三方网站，标记为cdn
	if strings.Contains(keyword, "(") && len(quakerespdata.Data) > 2000 {
		//99 代表可疑的搜索语句，可能不是目标单位，如果确定的话加入到target的yaml中
		targets.SearchStatus = 99
		return targets
	}
	gologger.Info().Msgf("[QUAKE] [%s] 已查询: %d/%d", keyword, len(quakerespdata.Data), len(quakerespdata.Data))
	var Domains []string
	var ips []string
	for _, d := range quakerespdata.Data {
		if d.Service.HTTP.Host != "" {
			//判断语法是不是domain=xxx或者host=xxx，结果会存在一些xxx.com.zzz.com，故意做的引流，检测是否是根域名，不是的话就下一个
			if strings.Contains(keyword, "domain=") || strings.Contains(keyword, "host=") {
				rootdomain, err := publicsuffix.EffectiveTLDPlusOne(d.Service.HTTP.Host)
				if err != nil {
					gologger.Error().Msg(err.Error())
				}
				keyworddomain := utils.FromQuakeKeywordGetDomain(keyword)
				if rootdomain != strings.TrimSpace(strings.ReplaceAll(keyworddomain, "\"", "")) {
					continue
				}
			}
			Domains = append(Domains, d.Service.HTTP.Host)
			if d.Port == 80 || d.Port == 443 {
				targets.Targets = append(targets.Targets, d.Service.HTTP.Host)
			} else {
				targets.Targets = append(targets.Targets, d.Service.HTTP.Host+":"+strconv.Itoa(d.Port))
			}
		} else {
			ips = append(ips, d.IP)
			if d.Port == 80 || d.Port == 443 {
				targets.Targets = append(targets.Targets, d.IP)
			} else {
				targets.Targets = append(targets.Targets, d.IP+":"+strconv.Itoa(d.Port))
			}
		}
	}
	Domains = utils.RemoveDuplicateElement(Domains)
	//如果语法是ip扫描，就不探测cdn了，而且ip也不会进入到ips库中继续等待扫描，因为使用的语法是/24，重复扫描
	//TODO 如果是domain那么前面就不添加对应的ip，避免是cdn节点，如果不是节点那么添加ip到ips表
	//if !strings.Contains(keyword, "ip=") && len(Domains) != 0 {
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
	//将不是cdn的domain解析ip放入targets
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
	return targets
}
