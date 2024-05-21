package main

import (
	"Findyou.TaskScheduling/common/db/mysqldb"
	"Findyou.TaskScheduling/common/db/redisdb"
	"Findyou.TaskScheduling/common/dbmaketask"
	"Findyou.TaskScheduling/common/makekeywords"
	"Findyou.TaskScheduling/common/taskstruct"
	"Findyou.TaskScheduling/common/utils"
	"github.com/projectdiscovery/gologger"
	"time"
)

func main() {
	//检查数据库状态，读取app.yaml和target.yaml
	appconfig, targetconfig := prepare()
	//从target.yaml生成对应平台的keywords并写入到mysql和redis
	if !targetconfig.OtherSet.DBScan {
		makekeywords.YAMLMakeKeywordsToDB(appconfig, targetconfig)
	} else {
		gologger.Info().Msg("跳过从配置文件生成任务")
	}
	//表中设置workflow状态，for循环探测到所有的status都是done且无任务且数据库无可生成的任务就结束
	for {
		//Done 改成获取tasks表中的状态，这样就不用多个表的判断了
		Status, count := mysqldb.CheckAllTasksStatus("Completed")
		if !Status {
			gologger.Info().Msgf("当前共 [%d] 任务未完成", count)
			//检查tasks表的失败和取消的任务并重新生成task
			err := dbmaketask.Taskmaketask("Failed")
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			err = dbmaketask.Taskmaketask("Cancelled")
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			//检查ips表并生成任务
			err = dbmaketask.IPsmaketask(appconfig, targetconfig)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			//检查domains表并生成任务,搜索语句和子域名爆破
			//托管的第三方公司，是否可以后面通过host和domain的组合语法，对出来的域名不进行后续的联想收集操作
			err = dbmaketask.Domainsmaketask(appconfig, targetconfig)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			//检查targets表并生成存活探测任务
			err = dbmaketask.TargetsMakeAliveScanTasks(appconfig, "Waiting")
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			//检查targets表并生成目录列表和指纹识别任务

			//探测是否redis为空，如果为空那么就重新提交Pending任务和target的waitscan任务
			if redisdb.RedisIsNull() {
				err := dbmaketask.Taskmaketask("Pending")
				if err != nil {
					gologger.Error().Msg(err.Error())
				}
			}
			//检查targets表并生成存活探测任务
			err = dbmaketask.TargetsMakeAliveScanTasks(appconfig, "WaitScan")
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			time.Sleep(30 * time.Second)
			continue
		}
		if mysqldb.CheckAllWorkflowStatus("Completed") && redisdb.RedisIsNull() {
			break
		}
		gologger.Info().Msg("Workflow状态未结束或任务列表有未完成的任务")
		time.Sleep(30 * time.Second)
	}
	gologger.Info().Msg("所有任务结束,调度模块即将停止")
	time.Sleep(10 * time.Second)
}

func prepare() (*taskstruct.Appconfig, *taskstruct.Targetconfig) {
	appconfig, targetconfig := utils.LoadConfig()
	mysqldb.CheckAndCreate(appconfig)
	taskstruct.CompanyID = make(map[string]uint)
	//从数据库中读取company信息并赋值给CompanyID
	mysqldb.DBCompaniesToStruct()
	mysqldb.YamlCompanyToDB(targetconfig)
	return appconfig, targetconfig
}
