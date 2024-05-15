package main

import (
	"Findyou.WorkFlow/common/db/redisdb"
	"Findyou.WorkFlow/common/httpxscan"
	"Findyou.WorkFlow/common/loadyaml"
	"Findyou.WorkFlow/common/onlineengine"
	"Findyou.WorkFlow/common/subdomainbrute"
	"Findyou.WorkFlow/common/utils"
	"github.com/projectdiscovery/gologger"
	"time"
)

func main() {
	loadyaml.Loadyaml()
	Workflowrun()
}

func Workflowrun() {
	appconfig := utils.GetAppConf()
	rediscon := redisdb.GetRedisClient()
	if rediscon == nil {
		gologger.Fatal().Msg("获取redis连接失败")
		return
	}
	for {
		gologger.Info().Msgf("当前workflow模块状态: \nFOFA搜索引擎:%v, HUNTER搜索引擎:%v, QUAKE搜索引擎:%v, CDN检查模块:%v, 子域名爆破模块:%v, 存活探测模块:%v, 目录扫描模块:%v, 指纹识别模块:%v, POC扫描模块:%v", appconfig.Module.Fofasearch, appconfig.Module.Huntersearch, appconfig.Module.Quakesearch, appconfig.Module.Cdncheck, appconfig.Module.Domainbrute, appconfig.Module.Alivescan, appconfig.Module.Dirbrute, appconfig.Module.Fingerprint, appconfig.Module.Pocscan)
		//TODO: 爱企查及企查查接口获取目标单位信息
		if redisdb.RedisIsNull() {
			gologger.Info().Msg("Redis 数据库为空，等待任务")
			time.Sleep(30 * time.Second)
			continue
		}
		key, value, err := redisdb.GetFromRedis(rediscon, appconfig)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		switch key {
		case "AQCQCCSCAN":
			gologger.Info().Msg("待实现")
		case "FOFASEARCH":
			onlineengine.FOFASearch(value, appconfig)
		case "HUNTERSEARCH":
			gologger.Info().Msg("待实现")
		case "SUBDOMAINBRUTE":
			subdomainbrute.SubdomainBrute(value)
			gologger.Info().Msg("待实现")
		case "ALIVESCAN":
			httpxscan.Httpxscan(value, appconfig)
		case "DIRBRUTE":
			gologger.Info().Msg("待实现")
		}
		//域名及CDN处理入库已经完成，全部放入domain库，后续直接读取iscdn为0的值对应的ip，并于ips目录ip进行对比然后加入到新的切片进行端口爆破及其他信息收集
		//TODO 子域名爆破，超过一百个就立即删除否则会爆内存
		//TODO 重点IP做单独的端口扫描，1.真实的解析ip2.搜索结果较多的ip段3.targets中最多端口的域名或ipTOP?
		//Done Httpx做存活扫描
		//TODO 域名绑定资产发现
		//TODO 目录扫描，常见目录比如子域名同名目录，app，test,login等,进行指纹识别
		//fingerprint.Fingerprint(appconfig)
		//TODO Poc识别
		//所有存活探测结束之后再做poc，防止被禁了ip导致其他后面的目标存活探测都为异常
		//pocs.PocScan()
	}

}
