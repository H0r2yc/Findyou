package onlineengine

import (
	"Findyou.WorkFlow/common/cdn"
	"Findyou.WorkFlow/common/db/mysqldb"
	"Findyou.WorkFlow/common/utils"
	"Findyou.WorkFlow/common/workflowstruct"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	"golang.org/x/net/publicsuffix"
	"io"
	"net/http"
	"strconv"
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

func FOFASearch(datalist []string, appconfig *workflowstruct.Appconfig) {
	status := true
	var companyid int
	if len(datalist) == 0 {
		gologger.Info().Msg("获取到的FOFASEARCH任务为空，退出")
	}
	gologger.Info().Msgf("获取到FOFASEARCH任务数量 [%d] ", len(datalist))
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
		result := SearchFOFACore(keywords[0], appconfig.API.Fofa.Key, 9000, appconfig.CDNConfig.CDNBruteForceThreads)
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
			result = SearchFOFACore(keywords[0], appconfig.API.Fofa.Key, 9000, appconfig.CDNConfig.CDNBruteForceThreads)
			if result.SearchStatus != 1 && result.SearchStatus != 99 {
				gologger.Info().Msg("状态异常，10秒后重试中...")
				time.Sleep(10 * time.Second)
				result = SearchFOFACore(keywords[0], appconfig.API.Fofa.Key, 9000, appconfig.CDNConfig.CDNBruteForceThreads)
				if result.SearchStatus != 1 && result.SearchStatus != 99 {
					gologger.Error().Msg("出错了，可能没有余额或者key错误，即将禁用workflow当前fofa搜索模块")
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

// 从Fofa中搜索目标
func SearchFOFACore(keyword, fofakey string, pageSize, cdnthread int) workflowstruct.Targets {
	targets := workflowstruct.Targets{
		DomainIps: make(map[string][]string),
	}
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)
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
	//TODO 返回类型包含归属地和hash方便后面生成keyword
	q.Add("fields", "host,protocol,ip,port,domain")
	q.Add("full", "false")
	req.URL.RawQuery = q.Encode()

	// 确保不会超速
	time.Sleep(time.Second * 1)

	resp, errDo := client.Do(req)
	if errDo != nil {
		gologger.Error().Msgf("[Fofa] [%s] 资产查询失败！请检查网络状态。Error:%s", keyword, errDo.Error())
		targets.SearchStatus = 0
		return targets
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		targets.SearchStatus = 2
		gologger.Error().Msgf("[Fofa] 获取Fofa 响应Body失败: %v", err.Error())
		return targets
	}

	var responseJson FOFAResponseJson
	if err = json.Unmarshal(data, &responseJson); err != nil {
		targets.SearchStatus = 2
		gologger.Error().Msgf("[Fofa] 返回数据Json解析失败! Error:%s", err.Error())
		return targets
	}

	if responseJson.Error {
		targets.SearchStatus = 2
		gologger.Error().Msgf("[Fofa] [%s] 搜索失败！返回响应体Error为True。返回信息: %v", keyword, string(data))
		return targets
	}

	if responseJson.Size == 0 {
		targets.SearchStatus = 1
		gologger.Info().Msgf("[Fofa] [%s] 无结果。", keyword)
		return targets
	}
	targets.SearchStatus = 1
	targets.SearchCount = uint(len(responseJson.Results))
	//如果是通过从db取出的domain然后查出的结果大于2000条，大概率是cdn等第三方网站，标记为cdn
	if strings.Contains(keyword, "(") && len(responseJson.Results) > 2000 {
		//99 代表可疑的搜索语句，可能不是目标单位，如果确定的话加入到target的yaml中
		targets.SearchStatus = 99
		return targets
	}
	gologger.Info().Msgf("[Fofa] [%s] 已查询: %d/%d", keyword, len(responseJson.Results), responseJson.Size)
	// 做一个域名缓存，避免重复dns请求
	var Domains []string
	var ips []string
	var protocol, ip, port, host, domain string
	for _, result := range responseJson.Results {
		host = result[0]
		protocol = result[1]
		ip = result[2]
		port = result[3]
		//去除一些受保护的空白数据以及ipv6
		if !utils.IsIPv4(ip) {
			continue
		}
		if port == "0" {
			continue
		}
		if protocol != "https" && protocol != "http" {
			protocol = "https"
		}
		//这儿赋值为""的目的是domain是根域名，不包含子域名，所有要后面处理后成为子域名
		domain = ""
		if result[4] != "" {
			//判断语法是不是domain=xxx或者host=xxx，结果会存在一些xxx.com.zzz.com，故意做的引流，检测是否是根域名，不是的话就下一个
			if strings.Contains(keyword, "domain=") || strings.Contains(keyword, "host=") {
				rootdomain, err := publicsuffix.EffectiveTLDPlusOne(result[4])
				if err != nil {
					gologger.Error().Msg(err.Error())
				}
				keyworddomain := utils.FromKeywordGetDomain(keyword)
				if rootdomain != strings.TrimSpace(strings.ReplaceAll(keyworddomain, "\"", "")) {
					continue
				}
			}
			realHost := strings.ReplaceAll(host, protocol+"://", "")
			domain = strings.ReplaceAll(realHost, ":"+port, "")
			Domains = append(Domains, domain)
			//如果不是常见端口，那么就加入一个url到target，如果是常规端口，那么直接加入域名到target，毕竟网络空间引擎并不能实时探测网站的状态，万一协议有变化
			if port != "80" && port != "443" {
				//这里添加的域名host直接到target只是一个端口，实际可能存在其他端口
				if strings.Contains(host, "://") {
					targets.Targets = append(targets.Targets, host)
				} else {
					targets.Targets = append(targets.Targets, protocol+"://"+host)
				}
			} else {
				targets.Targets = append(targets.Targets, domain)
			}
		} else {
			//这儿是ip添加到target的逻辑，和domain一样，如果不是常规端口就添加整个url,如果是常规端口就添加ip,毕竟网络空间引擎并不能实时探测网站的状态，万一协议有变化
			if port != "80" && port != "443" {
				if strings.Contains(host, "://") {
					targets.Targets = append(targets.Targets, host)
				} else {
					targets.Targets = append(targets.Targets, protocol+"://"+host)
				}
				if !strings.Contains(keyword, "ip=") {
					if !mysqldb.Isipclr(ip) {
						ips = append(targets.IPs, ip)
					}
				}
			} else {
				targets.Targets = append(targets.Targets, ip)
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
			targets.Targets = append(targets.Targets, d)
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
