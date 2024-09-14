package mysqldb

// ProcessTargets 处理从数据库中取出的数据，并设置相应的值
func ProcessTargets(target *Targets, Title string, status string, fingerprint string, url string, priority int) error {
	db := GetDB()
	mysqllock.Lock()
	defer mysqllock.Unlock()
	// 处理 targets
	if err := db.Model(target).Updates(map[string]interface{}{"Status": status, "Title": Title, "FingerPrint": fingerprint, "Priority": uint(priority), "Url": url}).Error; err != nil {
		return err
	}
	return nil
}

// ProcessTargetStatus 处理从数据库中取出的数据，并将 Status 设置为特定值
func ProcessTargetStatus(target *Targets, status string) error {
	db := GetDB()
	mysqllock.Lock()
	defer mysqllock.Unlock()
	// 处理 targets
	if err := db.Model(target).Updates(map[string]interface{}{"Status": status}).Error; err != nil {
		return err
	}
	return nil
}

// ProcessTargetFingerprint 处理从数据库中取出的数据，并将 fingerprint和等级 设置为特定值
func ProcessTargetFingerprint(target *Targets, fingerprint string) error {
	db := GetDB()
	mysqllock.Lock()
	defer mysqllock.Unlock()
	// 处理 targets
	if err := db.Model(target).Updates(map[string]interface{}{"FingerPrint": fingerprint, "Priority": 3}).Error; err != nil {
		return err
	}
	return nil
}

// ProcessHighLevelVuln 处理从数据库中取出的数据，并将 fingerprint和等级 设置为特定值
func ProcessHighLevelVuln(target *HighLevelTargets, fingerprint string) error {
	db := GetDB()
	mysqllock.Lock()
	defer mysqllock.Unlock()
	// 处理 targets
	if err := db.Model(target).Updates(map[string]interface{}{"finger": fingerprint, "Priority": 3}).Error; err != nil {
		return err
	}
	return nil
}

// ProcessTasks 处理从数据库中取出的数据，并将 Status 设置为特定值
func ProcessTasks(Tasks Tasks, status string) error {
	db := GetDB()
	mysqllock.Lock()
	defer mysqllock.Unlock()
	if err := db.Model(Tasks).Update("Status", status).Error; err != nil {
		return err
	}
	return nil
}

// ProcessTasksCount 处理从数据库中取出的数据，并将 Count 设置为特定值
func ProcessTasksCount(Tasks Tasks, count uint) error {
	db := GetDB()
	mysqllock.Lock()
	defer mysqllock.Unlock()
	if err := db.Model(Tasks).Update("Count", count).Error; err != nil {
		return err
	}
	return nil
}

// ProcessTasksNote 处理从数据库中取出的数据，并将 Note 设置为特定值
func ProcessTasksNote(Tasks Tasks, note string) error {
	db := GetDB()
	mysqllock.Lock()
	defer mysqllock.Unlock()
	if err := db.Model(Tasks).Update("Note", note).Error; err != nil {
		return err
	}
	return nil
}
