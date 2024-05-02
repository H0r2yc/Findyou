package config

import (
	"math/rand"
	"time"
)

var NoProxyByCmd bool

// GetProxyConfig 从配置文件中获取一个代理配置参数，多个代理则随机选取一个
func GetProxyConfig() string {
	if NoProxyByCmd {
		return ""
	}
	config := GetAppConf()
	if len(config.Proxy.Host) == 0 {
		return ""
	}
	if len(config.Proxy.Host) == 1 {
		return config.Proxy.Host[0]
	}
	if len(config.Proxy.Host) > 1 {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		n := r.Intn(len(config.Proxy.Host))
		return config.Proxy.Host[n]
	}
	return ""
}
