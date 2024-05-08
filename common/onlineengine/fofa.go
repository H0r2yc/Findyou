package onlineengine

import (
	"Findyou/common/cdn"
	"Findyou/common/config"
	"Findyou/common/db"
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
	KeyWords := FofaMakeKeyword(targetlist)
	gologger.Info().Msgf("准备从fofa获取数据")
	for _, keyword := range KeyWords {
		result := SearchFOFACore(keyword, fofakey, 9000, cdnthread)
		//searchkeywords.SearchCount = append(searchkeywords.SearchCount, result.SearchCount)
		//searchkeywords.SearchStatus = append(searchkeywords.SearchStatus, result.SearchStatus)
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
		//keyword入库的部分
		err = KeywordToDB(keyword, result)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}
	//keyword入库的部分
	//err := KeywordsToDB(searchkeywords)
	//if err != nil {
	//	gologger.Error().Msg(err.Error())
	//}
}

func FOFADBSearch(datalist, globalkeywords []string, fofakey, datatype string, cdnthread int) {
	for _, data := range datalist {
		var success bool = true
		Keywords := DBMakeKeyword(globalkeywords, data, datatype)
		for _, keyword := range Keywords {
			result := SearchFOFACore(keyword, fofakey, 9000, cdnthread)
			//searchkeywords.SearchCount = append(searchkeywords.SearchCount, result.SearchCount)
			//searchkeywords.SearchStatus = append(searchkeywords.SearchStatus, result.SearchStatus)
			if result.SearchStatus != 1 {
				success = false
				break
			}
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
			//keyword入库的部分
			err = KeywordToDB(keyword, result)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
		}
		//实时修改数据库使用过的数据状态
		if !success {
			gologger.Error().Msg("出错了，不进行操作并退出当前模块进行下一步")
			break
		}
		if datatype == "IP" {
			IPdbdata, err := db.GetIPs(data)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			err = db.ProcessIPs(IPdbdata, 1)
			if err != nil {
				gologger.Error().Msgf("Failed to process ips: %s", err.Error())
			}
		} else if datatype == "Domains" {
			Domaindbdata, err := db.GetDomain(data)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			err = db.ProcessDomains(Domaindbdata, 1)
			if err != nil {
				gologger.Error().Msgf("Failed to process domains: %s", err.Error())
			}
		}
	}
	//keyword入库的部分
	//err := KeywordsToDB(searchkeywords)
	//if err != nil {
	//	gologger.Error().Msg(err.Error())
	//}

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
	//TODO 返回类型包含归属地和hash方便后面生成keyword
	q.Add("fields", "host,protocol,title,icp,ip,port,domain")
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
		gologger.Error().Msgf("[Fofa] [%s] 无结果。", keyword)
		return targets
	}
	targets.SearchStatus = 1
	targets.SearchCount = uint(len(responseJson.Results))
	gologger.Info().Msgf("[Fofa] [%s] 已查询: %d/%d", keyword, len(responseJson.Results), responseJson.Size)
	// 做一个域名缓存，避免重复dns请求
	var Domains []string
	var ips []string
	DomainIPMap := make(map[string]string)
	domainCDNMap := make(map[string]bool)
	var protocol, ip, port, host, domain string
	for _, result := range responseJson.Results {
		host = result[0]
		protocol = result[1]
		ip = result[4]
		port = result[5]
		//去除一些受保护的空白数据以及ipv6
		if !utils.IsIPv4(ip) {
			continue
		}
		if port == "0" {
			continue
		}
		//这儿赋值为""的目的是domain是根域名，不包含子域名，所有要后面处理后成为子域名
		domain = ""
		if result[6] != "" {
			//这里添加的域名host直接到target只是一个端口，实际可能存在其他端口
			if strings.Contains(host, "://") {
				targets.Targets = append(targets.Targets, host)
			} else {
				targets.Targets = append(targets.Targets, protocol+"://"+host)
			}
			realHost := strings.ReplaceAll(host, protocol+"://", "")
			domain = strings.ReplaceAll(realHost, ":"+port, "")
			//添加domainIP的映射关系，并添加到待检测cdn的Domains中
			DomainIPMap[domain] = ip
			Domains = append(Domains, domain)
		} else {
			if strings.Contains(host, "://") {
				targets.Targets = append(targets.Targets, host)
			} else {
				targets.Targets = append(targets.Targets, protocol+"://"+host)
			}
			if !strings.Contains(keyword, "ip=") {
				if !db.Isipclr(result[4]) {
					ips = append(targets.IPs, result[4])
				}
			}
		}
	}

	Domains = utils.RemoveDuplicateElement(Domains)
	//如果语法是ip扫描，就不探测cdn了，而且ip也不会进入到ips库中继续等待扫描，因为使用的语法是/24，重复扫描
	//TODO 如果是domain那么前面就不添加对应的ip，避免是cdn节点，如果不是节点那么添加ip到ips表
	if !strings.Contains(keyword, "ip=") && len(Domains) != 0 {
		gologger.Info().Msgf("正在查询 [%v] 个域名是否为CDN资产", len(Domains))
		cdnDomains, normalDomains, _ := cdn.CheckCDNs(Domains, cdnthread)
		gologger.Info().Msgf("CDN资产为 [%v] 个", len(cdnDomains))
		for _, d := range cdnDomains {
			_, ok := domainCDNMap[d]
			if !ok {
				targets.Domains = append(targets.Domains, d)
				targets.IsCDN = append(targets.IsCDN, 1)
				targets.DomainIps = append(targets.DomainIps, "")
			}
		}
		for _, d := range normalDomains {
			_, ok := domainCDNMap[d]
			if !ok {
				targets.Domains = append(targets.Domains, d)
				targets.IsCDN = append(targets.IsCDN, 0)
				targets.DomainIps = append(targets.DomainIps, DomainIPMap[d])
			}
		}
	}
	//domain已经判断过是否重复
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
