package mysqldb

import "github.com/projectdiscovery/gologger"

// GetTasks 返回task对应的db结构体
func GetTasks(task string) (Tasks, error) {
	var tasks Tasks
	database := GetDB()
	mysqllock.Lock()
	defer mysqllock.Unlock()
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

// GetTarget 从数据库中取出特定target，因为在httpx多线程中，所以要添加一个锁
func GetTarget(Target string) (*Targets, error) {
	db := GetDB()
	mysqllock.Lock()
	defer mysqllock.Unlock()
	var targets *Targets
	result := db.Where("Target = ?", Target).Find(&targets)
	if result.Error != nil {
		return targets, result.Error
	}
	return targets, nil
}

// Get 从数据库中取出特定target，因为在httpx多线程中，所以要添加一个锁
func GetHignLevelVuln(HighLevelTarget string) (*HighLevelTargets, error) {
	db := GetDB()
	mysqllock.Lock()
	defer mysqllock.Unlock()
	var highLevelTargets *HighLevelTargets
	result := db.Where("Url = ?", HighLevelTarget).Find(&highLevelTargets)
	if result.Error != nil {
		return highLevelTargets, result.Error
	}
	return highLevelTargets, nil
}

// GetTargetUrlID 从数据库中取出特定target，因为在httpx多线程中，所以要添加一个锁
func GetTargetUrlID(Url string) (*Targets, error) {
	db := GetDB()
	mysqllock.Lock()
	defer mysqllock.Unlock()
	var targets *Targets
	result := db.Where("Url = ?", Url).Find(&targets)
	if result.Error != nil {
		return targets, result.Error
	}
	return targets, nil
}
