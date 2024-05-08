package onlineengine

import (
	"Findyou/common/config"
	"Findyou/common/db"
	"github.com/projectdiscovery/gologger"
)

func SearchEngine(appconfig *config.Appconfig, targetlist *config.Targetconfig) {
	// 从Hunter中获取资产
	//if appconfig.OnlineAPI.IsHunter && !appconfig.OnlineAPI.IsFofa {
	//	config.GlobalConfig.Targets, _ = uncover.HunterSearch(config.GlobalConfig.Targets)
	//	return
	//}
	// 从Fofa中获取资产
	if appconfig.OnlineAPI.IsFofa && !appconfig.OnlineAPI.IsHunter {
		FOFASearch(targetlist, appconfig.API.Fofa.Key, appconfig.CDNConfig.CDNBruteForceThreads)
		return
	}
	/* 从Hunter中获取资产后使用Fofa进行端口补充。
	if appconfig.OnlineAPI.IsFofa && appconfig.OnlineAPI.IsHunter {
		targets, tIPs := uncover.HunterSearch(config.GlobalConfig.Targets)
		var querys []string
		for _, i := range tIPs {
			querys = append(querys, "ip=\""+i+"\"")
		}
		querys = utils.RemoveDuplicateElement(querys)
		config.GlobalConfig.Targets = uncover.FOFASearch(querys)
		config.GlobalConfig.Targets = append(config.GlobalConfig.Targets, targets...)
		config.GlobalConfig.Targets = utils.RemoveDuplicateElement(config.GlobalConfig.Targets)
		return
	}
	// 从Quake获取资产
	if appconfig.OnlineAPI.IsQuake {
		config.GlobalConfig.Targets = uncover.QuakeSearch(config.GlobalConfig.Targets)
	}
	*/
}

func SearchEngineFromDB() {
	appconfig := config.GetAppConf()
	targetconfig := config.GetTargetConf()
	//开始从数据库中读取信息并进行多次重复的信息收集
	ips, err := db.GetAllIPs(0)
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return
	}
	var IPList []string
	for _, ip := range ips {
		IPList = append(IPList, ip.IP)
	}

	domains, err := db.GetAllDomains(0)
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return
	}
	var DomainList []string
	for _, domain := range domains {
		DomainList = append(DomainList, domain.Domain)
	}
	// 从Hunter中获取资产
	//if appconfig.OnlineAPI.IsHunter && !appconfig.OnlineAPI.IsFofa {
	//	config.GlobalConfig.Targets, _ = uncover.HunterSearch(config.GlobalConfig.Targets)
	//	return
	//}
	// 从Fofa中获取资产
	if appconfig.OnlineAPI.IsFofa && !appconfig.OnlineAPI.IsHunter {
		if targetconfig.OtherSet.DomainCollect {
			FOFADBSearch(DomainList, targetconfig.Target.Gobal_keywords, appconfig.API.Fofa.Key, "Domains", appconfig.CDNConfig.CDNBruteForceThreads)
		}
		FOFADBSearch(IPList, targetconfig.Target.Gobal_keywords, appconfig.API.Fofa.Key, "IP", appconfig.CDNConfig.CDNBruteForceThreads)
		return
	}
	/* 从Hunter中获取资产后使用Fofa进行端口补充。
	if appconfig.OnlineAPI.IsFofa && appconfig.OnlineAPI.IsHunter {
		targets, tIPs := uncover.HunterSearch(config.GlobalConfig.Targets)
		var querys []string
		for _, i := range tIPs {
			querys = append(querys, "ip=\""+i+"\"")
		}
		querys = utils.RemoveDuplicateElement(querys)
		config.GlobalConfig.Targets = uncover.FOFASearch(querys)
		config.GlobalConfig.Targets = append(config.GlobalConfig.Targets, targets...)
		config.GlobalConfig.Targets = utils.RemoveDuplicateElement(config.GlobalConfig.Targets)
		return
	}
	// 从Quake获取资产
	if appconfig.OnlineAPI.IsQuake {
		config.GlobalConfig.Targets = uncover.QuakeSearch(config.GlobalConfig.Targets)
	}

	//全部运行后将取出来的视为已经使用，将所有已经用过的ip和domains都修改状态
	for _, ip := range ips {
		err = db.ProcessIPs(ip, 1)
		if err != nil {
			gologger.Error().Msgf("Failed to process ips: %s", err.Error())
		}
	}
	for _, domain := range domains {
		err = db.ProcessDomains(domain, 1)
		if err != nil {
			gologger.Error().Msgf("Failed to process domains: %s", err.Error())
		}
	}
	*/
}
