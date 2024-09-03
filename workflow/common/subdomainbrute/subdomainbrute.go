package subdomainbrute

import (
	"Findyou.WorkFlow/common/cdn"
	"Findyou.WorkFlow/common/db/mysqldb"
	"Findyou.WorkFlow/common/utils"
	"Findyou.WorkFlow/common/workflowstruct"
	_ "embed"
	"github.com/projectdiscovery/dnsx/calldnsx"
	"github.com/projectdiscovery/gologger"
	"strconv"
	"strings"
)

//go:embed dict/subdomains.txt
var subdomainfile string

func SubdomainBrute(datas []string) error {
	for _, data := range datas {
		subdomains := workflowstruct.Subdomains{
			SubdomainIPs: make(map[string][]string),
		}
		var companyid int
		var alivesubdomain []string
		domainid := strings.SplitN(data, "Findyou", 2)
		domain := domainid[0]
		//取到的任务爆破成功的和domains里面的domain列进行比对然后写入为Waiting,并添加到targets中，然后统一进行目录扫描
		gologger.Info().Msgf("获取到SUBDOMAINBRUTE任务 [%s]", domain)
		SubDomainTask, err := mysqldb.GetTasks(domain)
		//修改状态为Processing
		if err != nil {
			gologger.Error().Msgf("没有在数据库中找到对应的task")
		} else {
			err = mysqldb.ProcessTasks(SubDomainTask, "Processing")
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
		}
		gologger.Info().Msg("开始被动扫描获取子域名")
		subfindersubdomain, err := subfinder(domain)
		if err != nil {
			gologger.Error().Msg("被动获取子域名任务失败 " + err.Error())
		}
		alivesubdomain = append(alivesubdomain, subfindersubdomain...)
		gologger.Info().Msg("开始子域名爆破")
		subdomainbrute := calldnsx.CallDNSX(domain, subdomainfile)
		if len(subdomainbrute) > 400 {
			gologger.Info().Msgf("子域名 [%v] 爆破数量过多，跳过入库", domain)
			err = mysqldb.ProcessTasks(SubDomainTask, "数量过多已跳过主动爆破")
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
		} else {
			alivesubdomain = append(alivesubdomain, subdomainbrute...)
		}
		if len(alivesubdomain) > 0 {
			alivesubdomain = utils.RemoveDuplicateElement(alivesubdomain)
			//先进行cdn识别，获取到是否为CDN
			gologger.Info().Msgf("正在查询 [%v] 个域名是否为CDN资产", len(alivesubdomain))
			cdnDomains, normalDomains, domainips := cdn.CheckCDNs(alivesubdomain, 500)
			gologger.Info().Msgf("CDN资产为 [%v] 个", len(cdnDomains))
			for _, d := range cdnDomains {
				subdomains.Subdomains = append(subdomains.Subdomains, d)
			}
			for _, d := range normalDomains {
				subdomains.Subdomains = append(subdomains.Subdomains, d)
				// 域名和ip对应关系
				//如果解析失败了，那么就以0.0.0.0替代
				if domainips[d] != nil {
					subdomains.SubdomainIPs[d] = domainips[d]
				} else {
					subdomains.SubdomainIPs[d] = []string{"0.0.0.0"}
				}
			}
			//入库操作,入domain、ip和tatgets库，调度模块只使用rootdomain，不用考虑任务重复问题
			if len(domainid) > 1 {
				companyid, err = strconv.Atoi(domainid[1])
				if err != nil {
					companyid = 0
				}
			} else {
				gologger.Error().Msgf("找不到读取的companyid值，读取的内容为%s", data)
				companyid = 0
			}
			err = mysqldb.TargetsToDB(subdomains.Subdomains, uint(companyid), SubDomainTask.ID)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			err = mysqldb.DomainsToDB(subdomains.Subdomains, subdomains.SubdomainIPs, uint(companyid))
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			err = mysqldb.ProcessTasks(SubDomainTask, "Completed")
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
		}
	}
	return nil
}
