package main

import (
	"Findyou.TaskScheduling/common/db/mysqldb"
	"Findyou.TaskScheduling/common/db/redisdb"
	"Findyou.TaskScheduling/common/dbmaketask"
	"Findyou.TaskScheduling/common/makekeywords"
	"Findyou.TaskScheduling/common/taskstruct"
	"Findyou.TaskScheduling/common/utils"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	"os"
	"time"
)

// 存活探测使用被动识别后的已经存活目标生成任务
func main() {
	fileWriter, err := NewFileWriter("taskscheduling.log")
	if err != nil {
		fmt.Println("Error creating file writer:", err)
		return
	}
	consoleWriter := &ConsoleWriter{}
	multiWriter := NewMultiWriter(fileWriter, consoleWriter)
	gologger.DefaultLogger.SetWriter(multiWriter)

	//检查数据库状态，读取app.yaml和target.yaml
	appconfig, targetconfig := prepare()
	//从target.yaml生成对应平台的keywords并写入到mysql和redis
	if !targetconfig.OtherSet.DBScan {
		makekeywords.YAMLMakeTasksToDB(appconfig, targetconfig)
	} else {
		gologger.Info().Msg("跳过从配置文件生成任务")
	}
	//表中设置workflow状态，for循环探测到所有的status都是done且无任务且数据库无可生成的任务就结束
	for {
		//Done 改成获取tasks表中的状态，这样就不用多个表的判断了
		Status, count := mysqldb.CheckAllTasksStatus("Completed")
		if !Status {
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
			err = dbmaketask.TargetsMakeTasks("Waiting", "ALIVEANDPASSIVITYSCAN", "WaitAliveScan", appconfig.Splittodb.AliveScan)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			//检查targets表并生成目录列表和指纹识别任务
			err = dbmaketask.TargetsMakeTasks("存活", "DIRBRUTEANDPASSIVITYSCAN", "WaitDirBrute", appconfig.Splittodb.DirBrute)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			//检查targets表并生成主动指纹识别任务
			err = dbmaketask.TargetsMakeTasks("DirBruteComleted", "ACTIVEFINGERPRINT", "WaitActiveFinger", appconfig.Splittodb.ActiveFingers)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			//探测是否redis为空，如果为空那么就重新提交Pending任务和target的waitscan任务
			if redisdb.RedisIsNull() {
				gologger.Info().Msg("redis为空且有任务未完成，等待4分钟重新提交任务")
				time.Sleep(240 * time.Second)
				//在获取一次是否有新增的数据，如果没有的话就继续，有bug
				Status, _ = mysqldb.CheckAllTasksStatus("Completed")
				if !Status {
					err := dbmaketask.Taskmaketask("Pending")
					if err != nil {
						gologger.Error().Msg(err.Error())
					}
					//检查targets表并生成存活探测任务
					err = dbmaketask.TargetsMakeTasks("WaitAliveScan", "ALIVEANDPASSIVITYSCAN", "WaitAliveScan", appconfig.Splittodb.AliveScan)
					if err != nil {
						gologger.Error().Msg(err.Error())
					}
				}
			}
			gologger.Info().Msgf("当前共 [%d] 任务未完成", count)
			time.Sleep(30 * time.Second)
			continue
		}
		if mysqldb.CheckAllWorkflowStatus("Completed") && redisdb.RedisIsNull() {
			break
		}
		gologger.Info().Msg("Workflow状态未结束或任务列表有未完成的任务")
		time.Sleep(30 * time.Second)
	}
	gologger.Info().Msg("所有任务结束,调度模块即将停止\n可能为cdn的域名，如有误报请手动添加到yaml文件中")
	cdntask, err := mysqldb.GetAllCDNTask()
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	for _, task := range cdntask {
		gologger.Info().Msg(utils.FromKeywordGetDomain(task.Task))
	}
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

// MultiWriter 实现了 Writer 接口，并能够将日志写入多个输出目标
type MultiWriter struct {
	writers []writer.Writer
}

// NewMultiWriter 创建一个 MultiWriter 实例
func NewMultiWriter(writers ...writer.Writer) *MultiWriter {
	return &MultiWriter{writers: writers}
}

// Write 方法会将日志信息写入所有目标
func (m *MultiWriter) Write(data []byte, level levels.Level) {
	for _, writer := range m.writers {
		writer.Write(data, level)
	}
}

// FileWriter 实现了 Writer 接口，并将日志写入文件
type FileWriter struct {
	file *os.File
}

// NewFileWriter 创建一个 FileWriter 实例
func NewFileWriter(filename string) (*FileWriter, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}
	return &FileWriter{file: file}, nil
}

// Write 将日志信息写入文件
func (f *FileWriter) Write(data []byte, level levels.Level) {
	f.file.Write(data)
}

// ConsoleWriter 实现了 Writer 接口，并将日志信息写入控制台
type ConsoleWriter struct{}

// Write 将日志信息输出到控制台
func (c *ConsoleWriter) Write(data []byte, level levels.Level) {
	fmt.Print(string(data) + "\n")
}
