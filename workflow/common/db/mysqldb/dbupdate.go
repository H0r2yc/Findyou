package mysqldb

// ProcessTargets 处理从数据库中取出的数据，并将 Status 设置为特定值
func ProcessTargets(target *Targets, Title string, status string) error {
	db := GetDB()
	defer CloseDB(db)
	// 处理 targets
	// 设置 Status 为 1
	if err := db.Model(target).Updates(map[string]interface{}{"Status": status, "Title": Title}).Error; err != nil {
		return err
	}
	return nil
}

// ProcessTasks 处理从数据库中取出的数据，并将 Status 设置为特定值
func ProcessTasks(Tasks Tasks, status string) error {
	db := GetDB()
	defer CloseDB(db)
	// 设置 Status 为 1
	if err := db.Model(Tasks).Update("Status", status).Error; err != nil {
		return err
	}
	return nil
}

// ProcessTasksCount 处理从数据库中取出的数据，并将 Count 设置为特定值
func ProcessTasksCount(Tasks Tasks, count uint) error {
	db := GetDB()
	defer CloseDB(db)
	// 设置 Status 为 1
	if err := db.Model(Tasks).Update("Count", count).Error; err != nil {
		return err
	}
	return nil
}
