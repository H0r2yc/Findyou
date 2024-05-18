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
	var splitslice [][]string
	var tasks []mysqldb.Tasks
	waittargets, err := mysqldb.GetTargets("Waiting", true)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return err
	}
	if len(waittargets) == 0 {
		return nil
	}
	for _, target := range waittargets {
		alivescanlist = append(alivescanlist, target.Target)
	}
	if len(alivescanlist) != 0 {
		if len(alivescanlist) <= 500 {
			//写入keywords到tasks，状态waitting
			tasks, err = mysqldb.WriteNoFindyouToTasks(alivescanlist, "ALIVESCAN")
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			if tasks == nil {
				return nil
			}
			err = redisdb.WriteDataToRedis(rediscon, "ALIVESCAN", alivescanlist)
			if err != nil {
				fmt.Println("Error writing data to Redis:", err)
				return err
			}
		} else {
			splitslice = utils.SplitSlice(alivescanlist, len(alivescanlist)/appconfig.Splittodb.Workflow)
			//写入alivelist到tasks，状态waitting
			tasks, err = mysqldb.WriteTargetsToTasks(splitslice, len(splitslice), "ALIVESCAN")
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
		err = mysqldb.UpdateTargetsStatus(target, "WaitScan")
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}
	gologger.Info().Msgf("[%d] 个target已生成 [%d] 个任务", len(waittargets), len(splitslice))
	return nil
}
