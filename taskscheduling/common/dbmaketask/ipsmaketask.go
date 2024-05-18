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

func IPsmaketask(appconfig *taskstruct.Appconfig, targetconfig *taskstruct.Targetconfig) error {
	rediscon := redisdb.GetRedisClient()
	var fofakeywords []string
	//var hunterkeywords []string
	//var quakekeywords []string
	var splitslice [][]string
	waitips, err := mysqldb.GetAllIPs("Waiting", true)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return err
	}
	if len(waitips) == 0 {
		return nil
	}
	for _, task := range waitips {
		keyword := makekeywords.Makekeywordfromdb(appconfig, targetconfig, task.IP, "IP", task.CompanyID)
		fofakeywords = append(fofakeywords, keyword.FofaKeyWords...)
	}
	if len(fofakeywords) != 0 {
		//写入keywords到tasks，状态waitting
		tasks, err := mysqldb.WriteKeywordsToTasks(fofakeywords, "FOFASEARCH")
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		if tasks == nil {
			return nil
		}
		//写入处理过的纯keywords到keywords表
		keywords := utils.TaskDataToKeywordData(fofakeywords)
		err = mysqldb.WriteDataToKeywords(keywords)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		if len(fofakeywords) <= 100 {
			err = redisdb.WriteDataToRedis(rediscon, "FOFASEARCH", fofakeywords)
			if err != nil {
				fmt.Println("Error writing data to Redis:", err)
				return err
			}
		} else {
			splitslice = utils.SplitSlice(fofakeywords, len(fofakeywords)/appconfig.Splittodb.Fofakeyword)
			for i := 0; i < len(splitslice); i++ {
				err = redisdb.WriteDataToRedis(rediscon, "FOFASEARCH", splitslice[i])
				if err != nil {
					fmt.Println("Error writing data to Redis:", err)
					return err
				}
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
	for _, ip := range waitips {
		err = mysqldb.UpdateIPsStatus(ip, "Completed")
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}
	gologger.Info().Msgf("[%d] 个ip已生成 [%d] 个任务", len(waitips), len(splitslice))
	return nil
}
