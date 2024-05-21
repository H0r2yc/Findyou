package dbmaketask

import (
	"Findyou.TaskScheduling/common/db/mysqldb"
	"Findyou.TaskScheduling/common/db/redisdb"
	"Findyou.TaskScheduling/common/taskstruct"
	"github.com/projectdiscovery/gologger"
)

func AliveUrlMakeTask(targetconfig *taskstruct.Targetconfig) error {
	rediscon := redisdb.GetRedisClient()
	var dirbrutelist []string
	alivetargets, err := mysqldb.GetTargets("存活", true)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return err
	}
	for _, target := range alivetargets {
		dirbrutelist = append(dirbrutelist, target.Target)
	}

	gologger.Info().Msg(rediscon.String())
	return nil
}
