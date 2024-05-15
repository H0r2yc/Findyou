package mysqldb

// UpdateTasksStatus 处理从数据库中取出的数据，并将 Status 设置为 1
func UpdateTasksStatus(keywords Tasks, status string) error {
	db := GetDB()
	defer CloseDB(db)
	// 设置 Status
	if err := db.Model(keywords).Update("Status", status).Error; err != nil {
		return err
	}
	return nil
}

// UpdateIPsStatus 处理从数据库中取出的数据，并将 Status 设置为 1
func UpdateIPsStatus(keywords IPs, status string) error {
	db := GetDB()
	defer CloseDB(db)
	// 设置 Status
	if err := db.Model(keywords).Update("Status", status).Error; err != nil {
		return err
	}
	return nil
}

// UpdateDomainsStatus 处理从数据库中取出的数据，并将 Status 设置为 1
func UpdateDomainsStatus(keywords Domains, status string) error {
	db := GetDB()
	defer CloseDB(db)
	// 设置 Status
	if err := db.Model(keywords).Update("Status", status).Error; err != nil {
		return err
	}
	return nil
}

// UpdateTargetsStatus 处理从数据库中取出的数据，并将 Status 设置为 1
func UpdateTargetsStatus(keywords Targets, status string) error {
	db := GetDB()
	defer CloseDB(db)
	// 设置 Status
	if err := db.Model(keywords).Update("Status", status).Error; err != nil {
		return err
	}
	return nil
}
