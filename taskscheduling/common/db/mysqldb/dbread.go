package mysqldb

import (
	"github.com/projectdiscovery/gologger"
	"gorm.io/gorm"
)

// GetAllIPs 返回所有所有特定条件的ips
func GetAllIPs(status string, equalto bool) ([]IPs, error) {
	var ips []IPs
	var result *gorm.DB
	database := GetDB()
	defer CloseDB(database)
	if database == nil {
		gologger.Error().Msg("Failed to get database connection")
	}
	// 查询整个表
	if equalto {
		result = database.Where("Status = ?", status).Find(&ips)

	} else {
		result = database.Where("Status != ?", status).Find(&ips)

	}
	if result.Error != nil {
		return nil, result.Error
	}
	return ips, nil
}

// GetAllDomains 返回所有特定条件的domains
func GetAllDomains(status string, equalto bool) ([]Domains, error) {
	var domains []Domains
	var result *gorm.DB
	database := GetDB()
	if database == nil {
		gologger.Error().Msg("Failed to get database connection")
	}
	// 查询整个表
	if equalto {
		result = database.Where("Status = ?", status).Find(&domains)

	} else {
		result = database.Where("Status != ?", status).Find(&domains)

	}
	if result.Error != nil {
		return nil, result.Error
	}
	CloseDB(database)
	return domains, nil
}

// GetTargets 从数据库中取出所有特定条件的数据
func GetTargets(status string, equalto bool) ([]Targets, error) {
	var targets []Targets
	var result *gorm.DB
	database := GetDB()
	defer CloseDB(database)
	if database == nil {
		gologger.Error().Msg("Failed to get database connection")
	}
	// 查询整个表
	if equalto {
		result = database.Where("Status = ?", status).Find(&targets)

	} else {
		result = database.Where("Status != ?", status).Find(&targets)

	}
	if result.Error != nil {
		return nil, result.Error
	}
	return targets, nil
}

// GetAllTasks 从数据库中取出所有特定条件的数据
func GetAllTasks(status string, equalto bool) ([]Tasks, error) {
	var TaskList []Tasks
	var result *gorm.DB
	database := GetDB()
	defer CloseDB(database)
	if database == nil {
		gologger.Error().Msg("Failed to get database connection")
	}
	// 查询整个表
	if equalto {
		result = database.Where("Status = ?", status).Find(&TaskList)

	} else {
		result = database.Where("Status != ?", status).Find(&TaskList)

	}
	if result.Error != nil {
		return nil, result.Error
	}
	return TaskList, nil
}
