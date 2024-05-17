package dbmaketask

import (
	"Findyou.TaskScheduling/common/db/mysqldb"
	"Findyou.TaskScheduling/common/db/redisdb"
	"github.com/projectdiscovery/gologger"
	"strconv"
)

func Taskmaketask(status string) error {
	rediscon := redisdb.GetRedisClient()
	waittask, err := mysqldb.GetAllTasks(status, true)
	if err != nil {
		return err
	}
	if len(waittask) == 0 {
		return nil
	}
	gologger.Info().Msgf("重新提交状态为%s的任务 [%d] 个", status, len(waittask))
	for _, task := range waittask {
		switch task.TaskName {
		case "FOFASEARCH":
			redistaskdata := task.Task + "Findyou" + strconv.Itoa(int(task.CompanyID))
			err = redisdb.WriteDataToRedis(rediscon, task.TaskName, []string{redistaskdata})
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			err = mysqldb.UpdateTasksStatus(task, "Pending")
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
		case "ALIVESCAN":
			err = redisdb.WriteDataToRedis(rediscon, task.TaskName, []string{task.Task})
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			err = mysqldb.UpdateTasksStatus(task, "Pending")
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
		case "SUBDOMAINBRUTE":
			err = redisdb.WriteDataToRedis(rediscon, task.TaskName, []string{task.Task})
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			err = mysqldb.UpdateTasksStatus(task, "Pending")
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
		}

	}
	return err
}
