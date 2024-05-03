package config

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"log"
	"os"
	"path/filepath"
	"sync"
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
