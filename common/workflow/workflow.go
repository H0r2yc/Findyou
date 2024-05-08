package workflow

import (
	"Findyou/common/config"
	"Findyou/common/fingerprint"
	"Findyou/common/httpxscan"
	"Findyou/common/onlineengine"
	"Findyou/common/pocs"
	"github.com/projectdiscovery/gologger"
	"strings"
	"time"
)

func LoadConfig() (*config.Appconfig, *config.Targetconfig) {
	appconfig := config.GetAppConf()
	targetconfig := config.GetTargetConf()
	if appconfig != nil && targetconfig != nil {
		gologger.Info().Msgf("目标:%s, 域名:%s, IP:%s, 证书:%s, 重点地区:%s\nfofa自定义语法为:%s\nhunter自定义语法为:%s\nquake自定义语法为:%s\n全局关键字:%s\n", targetconfig.Target.Name, targetconfig.Target.Domain, targetconfig.Target.IP, targetconfig.Target.Cert, targetconfig.Target.City, targetconfig.Customizesyntax.Fofa, targetconfig.Customizesyntax.Hunter, targetconfig.Customizesyntax.Quake, strings.Join(targetconfig.Target.Gobal_keywords, ", "))
		time.After(5 * time.Second)
	}
	return appconfig, targetconfig
}

func startenginesearch(appconfig *config.Appconfig, targetconfig *config.Targetconfig) {
	if !targetconfig.OtherSet.DBScan {
		onlineengine.SearchEngine(appconfig, targetconfig)
	} else {
		gologger.Info().Msg("直接从数据库中的数据开始扫描")
	}
	//联想收集
	for i := 0; i < targetconfig.Customizesyntax.SearchLevel; i++ {
		gologger.Info().Msgf("联想收集第 [%d] 次", i+1)
		gologger.Info().Msgf("准备从fofa获取数据")
		onlineengine.SearchEngineFromDB()
	}
}

func Workflowrun() {
	appconfig, targetconfig := LoadConfig()
	//TODO: 爱企查及企查查接口获取目标单位信息
	//搜索引擎搜索
	startenginesearch(appconfig, targetconfig)
	//域名及CDN处理入库已经完成，全部放入domain库，后续直接读取iscdn为0的值对应的ip，并于ips目录ip进行对比然后加入到新的切片进行端口爆破及其他信息收集
	//TODO 域名爆破，超过一百个就立即删除否则会爆内存
	//TODO 重点IP做单独的端口扫描，1.真实的解析ip2.搜索结果较多的ip段3.targets中最多端口的域名或ipTOP?
	//Done Httpx做存活扫描
	httpxscan.Httpxscan(appconfig)
	//TODO 域名绑定资产发现
	//TODO 目录扫描，常见目录比如子域名同名目录，app，test,login等,进行指纹识别
	fingerprint.Fingerprint(appconfig)
	//TODO Poc识别
	if appconfig.Pocscan.Enable {
		gologger.Info().Msg("Poc扫描启用")
		pocs.PocScan()
	} else {
		gologger.Info().Msg("Poc扫描未启用，跳过")
	}
}
