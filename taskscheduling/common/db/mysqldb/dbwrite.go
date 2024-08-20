package mysqldb

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"gorm.io/gorm"
	"strconv"
	"strings"
)

func WriteToCompany(db *gorm.DB, company Company) error {
	// 将公司插入到数据库中
	if err := db.Create(&company).Error; err != nil {
		return err
	}
	return nil
}

func WriteToKeywords(db *gorm.DB, keywords Keywords) error {
	if err := db.Create(&keywords).Error; err != nil {
		gologger.Error().Msg(err.Error())
		return err
	}
	return nil
}

func WriteToTasks(db *gorm.DB, tasks Tasks) error {
	if err := db.Create(&tasks).Error; err != nil {
		gologger.Error().Msg(err.Error())
		return err
	}
	return nil
}

func WriteStringListToTasks(stringlist []string, TaskName string) ([]Tasks, error) {
	var tasks []Tasks
	database := GetDB()
	defer CloseDB(database)
	if database == nil {
		return nil, errors.New("获取数据库连接失败")
	}
	for _, keywords := range stringlist {
		keyword := strings.SplitN(keywords, "Findyou", 2)
		companyid, err := strconv.Atoi(keyword[1])
		if err != nil {
			companyid = 999
			gologger.Error().Msg(err.Error())
		}

		exists, err := CheckDuplicateRecordInTask(database, "Task", TaskName, keyword[0])
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		if exists {
			continue
		}
		id, err := GetNextID(database, "Tasks")
		if err != nil {
			gologger.Error().Msg(err.Error())
			continue
		}
		taskstruct := Tasks{
			ID:        id,
			TaskName:  TaskName,
			Task:      keyword[0],
			CompanyID: uint(companyid),
			Status:    "Waiting",
		}
		err = WriteToTasks(database, taskstruct)
		tasks = append(tasks, taskstruct)
	}
	return tasks, nil
}

func WriteNoFindyouToTasks(datas []string, TaskName string) ([]Tasks, error) {
	var tasks []Tasks
	database := GetDB()
	defer CloseDB(database)
	if database == nil {
		return nil, errors.New("获取数据库连接失败")
	}
	exists, err := CheckDuplicateRecordInTask(database, "Task", TaskName, strings.Join(datas, ","))
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	if exists {
		return tasks, nil
	}
	id, err := GetNextID(database, "Tasks")
	if err != nil {
		gologger.Error().Msg(err.Error())
		return tasks, errors.New("获取不到下一个TaskID")
	}
	taskstruct := Tasks{
		ID:       id,
		TaskName: TaskName,
		Task:     strings.Join(datas, ","),
		Status:   "Waiting",
	}
	err = WriteToTasks(database, taskstruct)
	tasks = append(tasks, taskstruct)
	return tasks, nil
}

func WriteTargetsToTasks(TargetsList [][]string, ListSize int, TaskName string) ([]Tasks, error) {
	if len(TargetsList) == 0 {
		gologger.Error().Msgf("%s 任务内容为空", TaskName)
		return nil, errors.New("任务列表为空")
	}
	var tasks []Tasks
	database := GetDB()
	defer CloseDB(database)
	if database == nil {
		return nil, errors.New("获取数据库连接失败")
	}
	for i := 0; i < ListSize; i++ {
		taskcontent := strings.Join(TargetsList[i], ",")
		exists, err := CheckDuplicateRecordInTask(database, "Task", TaskName, taskcontent)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		if exists {
			continue
		}
		id, err := GetNextID(database, "Tasks")
		if err != nil {
			gologger.Error().Msg(err.Error())
			continue
		}
		taskstruct := Tasks{
			ID:       id,
			TaskName: TaskName,
			Task:     taskcontent,
			Status:   "Waiting",
		}
		err = WriteToTasks(database, taskstruct)
		tasks = append(tasks, taskstruct)
	}
	return tasks, nil
}

func WriteDataToKeywords(keywords []string) error {
	database := GetDB()
	if database.Error != nil {
		return database.Error
	}
	for _, keyword := range keywords {
		exists, err := CheckDuplicateRecord(database, "Keywords", "Keyword", keyword)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		if exists {
			continue
		}
		keywordstruct := Keywords{
			Onlineengine: "FOFA",
			Keyword:      keyword,
		}
		err = WriteToKeywords(database, keywordstruct)
		if err != nil {
			gologger.Error().Msg(err.Error())
			return err
		}
	}
	return nil
}

func WriteToTargets(db *gorm.DB, Targets Targets) error {
	if err := db.Create(&Targets).Error; err != nil {
		gologger.Error().Msg(err.Error())
		return err
	}
	return nil
}
