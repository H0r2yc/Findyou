package dirbrute

import (
	"Findyou.WorkFlow/common/db/mysqldb"
	"Findyou.WorkFlow/common/fingerprint"
	"Findyou.WorkFlow/common/httpxscan"
	"Findyou.WorkFlow/common/workflowstruct"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"net/url"
	"strings"
)

func DirBrute(targets []string, appconfig *workflowstruct.Appconfig) {
	gologger.Info().Msgf("获取到DIRBRUTEANDACTIVEFINGER任务数量 [%d] 个", len(targets))
	taskstruct, err := mysqldb.GetTasks(strings.Join(targets, ","))
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	err = mysqldb.ProcessTasks(taskstruct, "Processing")
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	//设置可能存在漏洞的url列表
	var highlevellist []mysqldb.HighLevelTargets
	//开始生成目录扫描的列表
	var dirbrutetargets []string
	for _, target := range targets {
		subdomain, rooturl, err := extractSubdomainFromURL(target)
		if err != nil {
			fmt.Printf("Error parsing URL %s: %v\n", target, err)
		}
		if subdomain != "" {
			dirbrutetargets = append(dirbrutetargets, rooturl+"/"+subdomain)
		}
		dirbrutetargets = append(dirbrutetargets, rooturl+"/app")
		dirbrutetargets = append(dirbrutetargets, rooturl+"/home")
		dirbrutetargets = append(dirbrutetargets, rooturl+"/login")
		dirbrutetargets = append(dirbrutetargets, rooturl+"/nacos")

	}
	//先进行get探测加了目录的目标，将200的目标放入targets库，后面根据主动指纹库，对所有的目标进行批量识别，节省资源
	gologger.Info().Msg("开始目录扫描")
	//目录扫描不考虑ancn的问题
	urlentities, _ := httpxscan.Httpxscan(dirbrutetargets, appconfig.Httpxconfig.WebTimeout, appconfig.Httpxconfig.WebThreads, appconfig.Httpxconfig.HTTPProxy)
	//下面是被动信息收集和指纹识别,以及acn入库targets
	gologger.Info().Msg("开始信息收集和被动指纹检测")
	for _, urlentity := range urlentities {
		if urlentity.StatusCode < 200 || urlentity.StatusCode >= 500 {
			continue
		}
		//查找target,要和公司信息对应
		target, err := mysqldb.GetTargetID(urlentity.InputUrl)
		if err != nil {
			gologger.Error().Msg(err.Error())
			target.CompanyID = 999
		}
		//检测敏感信息
		bodydata := fingerprint.FindInBody(urlentity.Body)
		if bodydata.ICP != "" || bodydata.Supplychain != "" || bodydata.PhoneNum != "" {
			err = mysqldb.SensitiveInfoToDB(urlentity.Url, bodydata.PhoneNum, bodydata.Supplychain, bodydata.ICP)
			gologger.Info().Msgf("[INFOFIND] %s [%s] [%s] [%s]\n", urlentity.Url, bodydata.ICP, bodydata.PhoneNum, bodydata.Supplychain)
		}
		//被动检测指纹
		finger, priority, matched := fingerprint.Fingerprint(urlentity)
		if matched {
			gologger.Info().Msgf("[Finger] %s [%s] 等级：%d\n", urlentity.Url, finger, priority)
			highleveltarget := mysqldb.HighLevelTargets{
				Url:       urlentity.Url,
				Title:     urlentity.Title,
				Finger:    finger,
				Priority:  uint(priority),
				CompanyID: 0,
			}
			highlevellist = append(highlevellist, highleveltarget)
		}
		if urlentity.StatusCode == 200 || finger != "" || urlentity.Title != "" {
			err = mysqldb.TargetsToDB([]string{urlentity.Url}, target.CompanyID, taskstruct.ID, uint(priority), "存活", finger)
		}
		if err != nil {
			gologger.Error().Msgf("Failed to write dirbrute target: %s,url: %s", err.Error(), urlentity.Url)
		}
	}
	err = mysqldb.ProcessTasks(taskstruct, "Completed")
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	if len(highlevellist) != 0 {
		err = mysqldb.HighLevelTargetsToDB(highlevellist)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}
	gologger.AuditTimeLogger("目录扫描任务结束")
}

func getSubdomain(domain string) string {
	// 将域名按点分隔
	parts := strings.Split(domain, ".")

	// 如果域名长度大于 2，则表示可能有子域名
	if len(parts) > 2 {
		return parts[0] // 返回最前面的子域名
	}
	return "" // 如果是根域名或无法提取子域名，则返回空字符串
}

func extractSubdomainFromURL(inputURL string) (string, string, error) {
	if !strings.Contains(inputURL, "://") {
		// 如果没有协议，添加默认协议 http
		inputURL = "http://" + inputURL
	}
	// 解析 URL
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return "", "", err
	}

	// 提取域名（不包括协议部分）
	host := parsedURL.Host
	rooturl := fmt.Sprintf("%s://%s", parsedURL.Scheme, host)
	// 检查是否有子域名
	subdomain := getSubdomain(host)
	if subdomain != "" {
		return subdomain, rooturl, nil
	}

	// 如果没有子域名或是根域名
	return "", rooturl, nil
}
