package mysqldb

import "github.com/projectdiscovery/gologger"

// GetTasks 返回task对应的db结构体
func GetTasks(task string) (Tasks, error) {
	var tasks Tasks
	database := GetDB()
	defer CloseDB(database)
	if database == nil {
		gologger.Error().Msg("Failed to get database connection")
	}
	// 查询整个表
	result := database.Where("Task = ?", task).First(&tasks)
	if result.Error != nil {
		return tasks, result.Error
	}
	return tasks, nil
}

// GetAllTargets 从数据库中取出所有 Status 为 0 的数据
func GetAllTargets(status uint) ([]Targets, error) {
	db := GetDB()
	defer CloseDB(db)
	var targets []Targets
	result := db.Where("Status = ?", status).Find(&targets)
	if result.Error != nil {
		return nil, result.Error
	}
	return targets, nil
}

// GetTargetID 从数据库中取出所有 Status 为 0 的数据
func GetTargetID(Target string) (*Targets, error) {
	db := GetDB()
	defer CloseDB(db)
	var targets *Targets
	result := db.Where("Target = ?", Target).Find(&targets)
	if result.Error != nil {
		return targets, result.Error
	}
	return targets, nil
}
