package onlineengine

import (
	"Findyou/common/config"
	"Findyou/common/db"
	"github.com/projectdiscovery/gologger"
)

func SearchEngine() {
	appconfig := config.GetAppConf()
	targetlist := config.GetTargetConf()
	// 从Hunter中获取资产
	//if appconfig.OnlineAPI.IsHunter && !appconfig.OnlineAPI.IsFofa {
	//	config.GlobalConfig.Targets, _ = uncover.HunterSearch(config.GlobalConfig.Targets)
	//	return
	//}
	// 从Fofa中获取资产
	if appconfig.OnlineAPI.IsFofa && !appconfig.OnlineAPI.IsHunter {
		FOFASearch(targetlist, appconfig.API.Fofa.Key, appconfig.CDNConfig.SubdomainBruteForceThreads)
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
	ips, err := db.GetAllIPs()
	if err != nil {
		gologger.Error().Msgf(err.Error())
	}
	domains, err := db.GetAllDomains()
	if err != nil {
		gologger.Error().Msgf(err.Error())
	}

	// 从Hunter中获取资产
	//if appconfig.OnlineAPI.IsHunter && !appconfig.OnlineAPI.IsFofa {
	//	config.GlobalConfig.Targets, _ = uncover.HunterSearch(config.GlobalConfig.Targets)
	//	return
	//}
	// 从Fofa中获取资产
	if appconfig.OnlineAPI.IsFofa && !appconfig.OnlineAPI.IsHunter {
		FOFADBSearch(ips, targetconfig.Target.Gobal_keywords, appconfig.API.Fofa.Key, "IP", appconfig.CDNConfig.SubdomainBruteForceThreads)
		FOFADBSearch(domains, targetconfig.Target.Gobal_keywords, appconfig.API.Fofa.Key, "Domain", appconfig.CDNConfig.SubdomainBruteForceThreads)
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
