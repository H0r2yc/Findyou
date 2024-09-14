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
	var newtargets []string
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
		if taskname == "ALIVEANDPASSIVITYSCAN" {
			newtargets = append(newtargets, target.Target)
		} else {
			newtargets = append(newtargets, target.Url)
		}
	}
	if len(newtargets) != 0 {
		if len(newtargets) <= 200 {
			//写入keywords到tasks，状态waitting
			tasks, err = mysqldb.WriteNoFindyouToTasks(newtargets, taskname)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			if tasks == nil {
				return nil
			}
			err = redisdb.WriteDataToRedis(rediscon, taskname, newtargets)
			if err != nil {
				fmt.Println("Error writing data to Redis:", err)
				return err
			}
			taskcount = 1
		} else {
			splitslice = utils.SplitSlice(newtargets, len(newtargets)/listnum+1)
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
	gologger.Info().Msgf("[%d] 个target已生成 [%d] 个[%s]任务", len(waittargets), taskcount, taskname)
	return nil
}
