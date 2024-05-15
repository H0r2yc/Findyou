package utils

import (
	"Findyou.TaskScheduling/common/taskstruct"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

var targetyml = "config/target.yml"
var configyml = "config/app.yml"
var WorkerConfigReloadMutex sync.Mutex // worker读配置文件同步锁
var appconfig *taskstruct.Appconfig
var targetconfig *taskstruct.Targetconfig

func LoadConfig() (*taskstruct.Appconfig, *taskstruct.Targetconfig) {
	app := GetAppConf()
	target := GetTargetConf()
	if app != nil && target != nil {
		gologger.Info().Msgf("目标:%s, 域名:%s, IP:%s, 证书:%s, 重点地区:%s\nfofa自定义语法为:%s\nhunter自定义语法为:%s\nquake自定义语法为:%s\n全局关键字:%s\n", targetconfig.Target.Name, targetconfig.Target.Domain, targetconfig.Target.IP, targetconfig.Target.Cert, targetconfig.Target.City, targetconfig.Customizesyntax.Fofa, targetconfig.Customizesyntax.Hunter, targetconfig.Customizesyntax.Quake, strings.Join(targetconfig.Target.Gobal_keywords, ", "))
		time.After(5 * time.Second)
	}
	return app, target
}

func GetAppConf() *taskstruct.Appconfig {
	if appconfig == nil {
		appconfig = new(taskstruct.Appconfig)
		WorkerConfigReloadMutex.Lock()
		err := ReadConfig(configyml, "appconfig")
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

func GetTargetConf() *taskstruct.Targetconfig {
	if targetconfig == nil {
		targetconfig = new(taskstruct.Targetconfig)
		WorkerConfigReloadMutex.Lock()
		err := ReadConfig(targetyml, "targetconfig")
		if err != nil {
			log.Println(err)
		}
		WorkerConfigReloadMutex.Unlock()
		if err != nil {
			fmt.Println("Load config fail!")
			os.Exit(0)
		}
		return targetconfig
	} else {
		return targetconfig
	}
}

func ReadConfig(configyml, configtype string) error {
	fileContent, err := os.ReadFile(configyml)
	if err != nil {
		fmt.Println(err)
		return err
	}
	if configtype == "appconfig" {
		err = yaml.Unmarshal(fileContent, appconfig)
	} else if configtype == "targetconfig" {
		err = yaml.Unmarshal(fileContent, targetconfig)
	}
	if err != nil {
		fmt.Println(err)
	}
	return err
}
