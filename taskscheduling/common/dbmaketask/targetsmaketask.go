package dbmaketask

import (
	"Findyou.TaskScheduling/common/db/mysqldb"
	"Findyou.TaskScheduling/common/db/redisdb"
	"Findyou.TaskScheduling/common/utils"
	"fmt"
	"github.com/projectdiscovery/gologger"
)

func TargetsMakeTasks(status, taskname, taskstatus string, listnum int) error {
	rediscon := redisdb.GetRedisClient()
	var taskcount int
	var alivefingerlist []string
	var splitslice [][]string
	var tasks []mysqldb.Tasks
	waittargets, err := mysqldb.GetTargets(status, true)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return err
	}
	if len(waittargets) == 0 {
		return nil
	}
	for _, target := range waittargets {
		alivefingerlist = append(alivefingerlist, target.Target)
	}
	if len(alivefingerlist) != 0 {
		if len(alivefingerlist) <= 500 {
			//写入keywords到tasks，状态waitting
			tasks, err = mysqldb.WriteNoFindyouToTasks(alivefingerlist, taskname)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			if tasks == nil {
				return nil
			}
			err = redisdb.WriteDataToRedis(rediscon, taskname, alivefingerlist)
			if err != nil {
				fmt.Println("Error writing data to Redis:", err)
				return err
			}
			taskcount = 1
		} else {
			splitslice = utils.SplitSlice(alivefingerlist, len(alivefingerlist)/listnum+1)
			taskcount = len(splitslice)
			//写入alivelist到tasks，状态waitting
			tasks, err = mysqldb.WriteTargetsToTasks(splitslice, len(splitslice), taskname)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			for i := 0; i < len(splitslice); i++ {
				//先写入任务到mysql的task，状态waiting
				err = redisdb.WriteDataToRedis(rediscon, taskname, splitslice[i])
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
		err = mysqldb.UpdateTargetsStatus(target, taskstatus)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}
	gologger.Info().Msgf("[%d] 个target已生成 [%d] 个任务", len(waittargets), taskcount)
	return nil
}
