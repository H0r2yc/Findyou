package main

import (
	"Findyou/common/config"
	"Findyou/common/httpxscan"
	"Findyou/common/onlineengine"
	"fmt"
	"strings"
	"time"
)

func main() {
	workflowrun()
}

func LoadConfig() (*config.Appconfig, *config.Targetconfig) {
	appconfig := config.GetAppConf()
	targetconfig := config.GetTargetConf()
	if appconfig != nil && targetconfig != nil {
		fmt.Println("配置文件加载完成")
		fmt.Printf("目标:%s, 域名:%s, IP:%s, 证书:%s, 重点地区:%s\nfofa自定义语法为:%s\nhunter自定义语法为:%s\nquake自定义语法为:%s\n全局关键字:%s\n", targetconfig.Target.Name, targetconfig.Target.Domain, targetconfig.Target.IP, targetconfig.Target.Cert, targetconfig.Target.City, targetconfig.Customizesyntax.Fofa, targetconfig.Customizesyntax.Hunter, targetconfig.Customizesyntax.Quake, strings.Join(targetconfig.Target.Gobal_keywords, ", "))
		time.After(5 * time.Second)
	}
	return appconfig, targetconfig
}

func startenginesearch(appconfig *config.Appconfig, targetconfig *config.Targetconfig) {
	onlineengine.SearchEngine(appconfig, targetconfig)
	//onlineengine.SearchEngineFromDB()
}

func workflowrun() {
	appconfig, targetconfig := LoadConfig()
	//TODO: 爱企查及企查查接口获取目标单位信息
	//搜索引擎搜索
	startenginesearch(appconfig, targetconfig)
	//TODO 域名爆破
	//TODO 重点IP做单独的端口扫描，1.真实的解析ip2.搜索结果较多的ip3.targets中最多端口的域名或ip
	//Done Httpx做扫描
	httpxscan.Httpxscan(appconfig)
	//TODO 域名绑定资产发现
	//TODO 目录扫描，常见目录比如子域名同名目录，app，test,login等
	//TODO 指纹识别
	//TODO Poc识别
}
