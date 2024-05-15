package dbmaketask

import (
	"Findyou.TaskScheduling/common/db/mysqldb"
	"Findyou.TaskScheduling/common/db/redisdb"
	"Findyou.TaskScheduling/common/taskstruct"
	"Findyou.TaskScheduling/common/utils"
	"fmt"
	"github.com/projectdiscovery/gologger"
)

func TargetsMakeAliveScanTasks(appconfig *taskstruct.Appconfig) error {
	rediscon := redisdb.GetRedisClient()
	var alivescanlist []string
	waittargets, err := mysqldb.GetTargets("Waiting", true)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return err
	}
	if len(waittargets) == 0 {
		return nil
	}
	gologger.Info().Msgf("待生成task的targets数量 [%d]", len(waittargets))
	for _, target := range waittargets {
		alivescanlist = append(alivescanlist, target.Target)
	}
	if len(alivescanlist) != 0 {
		splitslice := utils.SplitSlice(alivescanlist, appconfig.Splittodb.Workflow)
		//写入alivelist到tasks，状态waitting
		tasks, err := mysqldb.WriteTargetsToTasks(splitslice, appconfig.Splittodb.Workflow, "ALIVESCAN")
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		for i := 0; i < len(splitslice); i++ {
			//先写入任务到mysql的task，状态waiting
			err = redisdb.WriteDataToRedis(rediscon, "ALIVESCAN", splitslice[i])
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
	//修改数据库中targets状态
	for _, target := range waittargets {
		err = mysqldb.UpdateTargetsStatus(target, "Completed")
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}
	return nil
}
