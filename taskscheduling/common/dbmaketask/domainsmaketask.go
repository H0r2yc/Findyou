package dbmaketask

import (
	"Findyou.TaskScheduling/common/db/mysqldb"
	"Findyou.TaskScheduling/common/db/redisdb"
	"Findyou.TaskScheduling/common/makekeywords"
	"Findyou.TaskScheduling/common/taskstruct"
	"Findyou.TaskScheduling/common/utils"
	"fmt"
	"github.com/projectdiscovery/gologger"
)

func Domainsmaketask(appconfig *taskstruct.Appconfig, targetconfig *taskstruct.Targetconfig) error {
	rediscon := redisdb.GetRedisClient()
	var fofakeywords []string
	//var hunterkeywords []string
	//var quakekeywords []string
	waitdomains, err := mysqldb.GetAllDomains("Waiting", true)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return err
	}
	if len(waitdomains) == 0 {
		return nil
	}
	gologger.Info().Msgf("待生成task的domains数量 [%d]", len(waitdomains))
	for _, task := range waitdomains {
		keyword := makekeywords.Makekeywordfromdb(appconfig, targetconfig, task.IP, "Domains", task.CompanyID)
		fofakeywords = append(fofakeywords, keyword.FofaKeyWords...)
		//hunterkeywords = append(hunterkeywords, keyword.HunterKeyWords...)
		//quakekeywords = append(quakekeywords, keyword.QuakeKeyWords...)
	}
	if len(fofakeywords) != 0 {
		//写入keywords到tasks，状态waitting
		tasks, err := mysqldb.WriteSearchwordToTasks(fofakeywords, "FOFASEARCH")
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		//写入处理过的纯keywords到keywords表
		keywords := utils.TaskDataToKeywordData(fofakeywords)
		err = mysqldb.WriteDataToKeywords(keywords)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}

		splitslice := utils.SplitSlice(fofakeywords, appconfig.Splittodb.Fofakeyword)
		for i := 0; i < len(splitslice); i++ {
			err = redisdb.WriteDataToRedis(rediscon, "FOFASEARCH", splitslice[i])
			if err != nil {
				fmt.Println("Error writing data to Redis:", err)
				return err
			}
		}
		for _, keyword := range tasks {
			err = mysqldb.UpdateTasksStatus(keyword, "Pending")
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
		}
	}
	//if len(xxxx)
	//修改数据库中ip状态
	for _, domain := range waitdomains {
		err = mysqldb.UpdateDomainsStatus(domain, "Completed")
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}
	return nil
}
