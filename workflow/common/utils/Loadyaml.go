package utils

import (
	"Findyou.WorkFlow/common/workflowstruct"
	"fmt"
	"gopkg.in/yaml.v2"
	"log"
	"math/rand"
	"os"
	"sync"
	"time"
)

var configyml = "config/app.yml"
var WorkerConfigReloadMutex sync.Mutex // worker读配置文件同步锁
var appconfig *workflowstruct.Appconfig

func GetAppConf() *workflowstruct.Appconfig {
	if appconfig == nil {
		appconfig = new(workflowstruct.Appconfig)
		WorkerConfigReloadMutex.Lock()
		err := ReadConfig(configyml)
		if err != nil {
			log.Println(err)
		}
		WorkerConfigReloadMutex.Unlock()
		if err != nil {
			fmt.Println("Load workflowstruct fail!")
			os.Exit(0)
		}
		return appconfig
	}
	return appconfig
}

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

func ReadConfig(configyml string) error {
	fileContent, err := os.ReadFile(configyml)
	if err != nil {
		fmt.Println(err)
		return err
	}
	err = yaml.Unmarshal(fileContent, appconfig)
	if err != nil {
		fmt.Println(err)
	}
	return err
}
