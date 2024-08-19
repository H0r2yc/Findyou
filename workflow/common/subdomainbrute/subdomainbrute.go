package subdomainbrute

import (
	"Findyou.WorkFlow/common/db/mysqldb"
	"github.com/projectdiscovery/gologger"
)

func SubdomainBrute(domains []string) error {
	for _, domain := range domains {
		//取到的任务爆破成功的和domains里面的domain列进行比对然后写入为Waiting,并添加到targets中，然后统一进行目录扫描
		gologger.Info().Msgf("获取到SUBDOMAINBRUTE任务 [%s]", domain)
		taskstruct, err := mysqldb.GetTasks(domain)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}

		err = mysqldb.ProcessTasks(taskstruct, "Completed")
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		return nil
	}
	return nil
}
