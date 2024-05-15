package makekeywords

import (
	"Findyou.TaskScheduling/common/db/mysqldb"
	"Findyou.TaskScheduling/common/db/redisdb"
	"Findyou.TaskScheduling/common/taskstruct"
	"Findyou.TaskScheduling/common/utils"
	"fmt"
	"github.com/projectdiscovery/gologger"
)

func YAMLMakeKeywordsToDB(appconfig *taskstruct.Appconfig, targetconfig *taskstruct.Targetconfig) {
	//从target.yaml生成对应平台的keywords并写入到redis
	gologger.Info().Msg("从配置文件生成任务")
	KeyWords := makekeywordfromyaml(appconfig, targetconfig)
	rediscon := redisdb.GetRedisClient()
	//defer之后会导致后续redis无法操作
	//defer redis.db.close()
	if KeyWords.FofaKeyWords != nil {
		//写入keywords到tasks，状态waitting
		tasks, err := mysqldb.WriteSearchwordToTasks(KeyWords.FofaKeyWords, "FOFASEARCH")
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		//写入处理过的纯keywords到keywords表
		keywords := utils.TaskDataToKeywordData(KeyWords.FofaKeyWords)
		err = mysqldb.WriteDataToKeywords(keywords)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		//写入keywords到redis
		//appconfig.Splittodb.Fofakeyword根据有几个fofakey以及几个workflow来决定
		splitslice := utils.SplitSlice(KeyWords.FofaKeyWords, appconfig.Splittodb.Fofakeyword)
		for i := 0; i < len(splitslice); i++ {
			exists, err := redisdb.IsDataInSet(rediscon, "FOFASEARCH", splitslice[i])
			if exists {
				continue
			}
			err = redisdb.WriteDataToRedis(rediscon, "FOFASEARCH", splitslice[i])
			if err != nil {
				fmt.Println("Error writing data to Redis:", err)
				return
			}
		}
		for _, keyword := range tasks {
			err = mysqldb.UpdateTasksStatus(keyword, "Pending")
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
		}
	}
	if KeyWords.HunterKeyWords != nil {
		//xxxx
	}
	gologger.Info().Msg("从配置文件生成任务成功")
}
