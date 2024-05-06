package config

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	Release = "Release" //正式运行模式
	Debug   = "Debug"   //开发模式
)

var targetyml = "config/target.yml"
var configyml = "config/app.yml"
var RunMode = Release
var WorkerConfigReloadMutex sync.Mutex // worker读配置文件同步锁
var appconfig *Appconfig
var targets *Targetconfig

func GetAppConf() *Appconfig {
	if appconfig == nil {
		appconfig = new(Appconfig)
		WorkerConfigReloadMutex.Lock()
		err := appconfig.ReadConfig()
		if err != nil {
			log.Println(err)
		}
		WorkerConfigReloadMutex.Unlock()
		if err != nil {
			fmt.Println("Load config fail!")
			os.Exit(0)
		}
		return appconfig
	}
	return appconfig
}

func GetTargetConf() *Targetconfig {
	if targets == nil {
		targets = new(Targetconfig)
		WorkerConfigReloadMutex.Lock()
		err := targets.ReadConfig()
		if err != nil {
			log.Println(err)
		}
		WorkerConfigReloadMutex.Unlock()
		if err != nil {
			fmt.Println("Load config fail!")
			os.Exit(0)
		}
		return targets
	} else {
		return targets
	}
}

func (config *Appconfig) ReadConfig() error {
	fileContent, err := os.ReadFile(filepath.Join(GetRootPath(), configyml))
	if err != nil {
		fmt.Println(err)
		return err
	}
	err = yaml.Unmarshal(fileContent, config)
	if err != nil {
		fmt.Println(err)
	}
	return err
}

func (config *Targetconfig) ReadConfig() error {
	fileContent, err := os.ReadFile(filepath.Join(GetRootPath(), targetyml))
	if err != nil {
		fmt.Println(err)
		return err
	}
	err = yaml.Unmarshal(fileContent, config)
	if err != nil {
		fmt.Println(err)
	}
	return err
}

// GetRootPath 获取运行时系统的root位置，解决调试时无法使用相对位置的困扰
func GetRootPath() string {
	if RunMode == Debug {
		return "/xxx/xxx"
	}
	return "."
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
