package makekeywords

import (
	"Findyou.TaskScheduling/common/db/mysqldb"
	"Findyou.TaskScheduling/common/db/redisdb"
	"Findyou.TaskScheduling/common/taskstruct"
	"Findyou.TaskScheduling/common/utils"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"strconv"
)

func YAMLMakeKeywordsToDB(appconfig *taskstruct.Appconfig, targetconfig *taskstruct.Targetconfig) {
	//从target.yaml生成对应平台的keywords并写入到redis
	gologger.Info().Msg("从配置文件生成任务")
	KeyWords := makekeywordfromyaml(appconfig, targetconfig)
	rediscon := redisdb.GetRedisClient()
	var splitslice [][]string
	//defer之后会导致后续redis无法操作
	//defer redis.db.close()
	if KeyWords.FofaKeyWords != nil {
		//写入keywords到tasks，状态waitting
		tasks, err := mysqldb.WriteKeywordsToTasks(KeyWords.FofaKeyWords, "FOFASEARCH")
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		//判断task是否为空，为空说明之前已经加载过配置文件内容到task，就不要执行写入到keywords表以及redis中了
		if tasks != nil {
			//判断是否有新增的资产，如果有就重新赋值FofaKeyWord，避免重复提交任务
			if len(tasks) != len(KeyWords.FofaKeyWords) {
				KeyWords.FofaKeyWords = []string{}
				for _, task := range tasks {
					KeyWords.FofaKeyWords = append(KeyWords.FofaKeyWords, task.Task+"Findyou"+strconv.Itoa(int(task.CompanyID)))
				}
			}
			//写入处理过的纯keywords到keywords表
			keywords := utils.TaskDataToKeywordData(KeyWords.FofaKeyWords)
			err = mysqldb.WriteDataToKeywords(keywords)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			//写入keywords到redis
			//如果大于100至少分成两份
			if len(KeyWords.FofaKeyWords) <= 100 {
				splitslice = utils.SplitSlice(KeyWords.FofaKeyWords, 2)
			} else {
				//appconfig.Splittodb.Fofakeyword根据最多数量来确定，目的是为了在出现问题的时候能在一定限度内控制将失败的task设置failed的状态，太多会造成后面资源的浪费
				splitslice = utils.SplitSlice(KeyWords.FofaKeyWords, len(KeyWords.FofaKeyWords)/appconfig.Splittodb.Fofakeyword+1)
			}
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
		} else {
			gologger.Info().Msg("已经从配置文件生成过相关任务，且无新增目标，跳过")
		}
	}
	if KeyWords.HunterKeyWords != "" {
		//xxxx
	}
	gologger.Info().Msg("从配置文件生成任务成功")
}
