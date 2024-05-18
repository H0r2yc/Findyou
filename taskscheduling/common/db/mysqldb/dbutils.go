package mysqldb

import (
	"Findyou.TaskScheduling/common/taskstruct"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"gorm.io/gorm"
)

// GetNextID 传入的table值为格式化后的表名
func GetNextID(db *gorm.DB, table string) (uint, error) {
	var maxID uint
	// 查询数据库表中最大的 target ID
	err := db.Table(table).Select("COALESCE(MAX(id), 0)").Scan(&maxID).Error
	if err != nil {
		return 0, err
	}

	// 下一个可用的 target ID 是最大的 target ID 加一
	nextID := maxID + 1
	return nextID, nil
}

// CheckDuplicateRecord 检查是否存在相同的数据，传入的表名和列名和申明的struct一致
func CheckDuplicateRecord(database *gorm.DB, tableName string, columnName string, data string) (bool, error) {
	// 查询数据库中是否存在相同的数据
	var existingRecord interface{}
	switch tableName {
	case "Company":
		existingRecord = &Company{}
	case "Domains":
		existingRecord = &Domains{}
	case "IPs":
		existingRecord = &IPs{}
	case "Fingerprints":
		existingRecord = &Fingerprints{}
	case "Targets":
		existingRecord = &Targets{}
	case "URLs":
		existingRecord = &URLs{}
	case "Keywords":
		existingRecord = &Keywords{}
	case "Tasks":
		existingRecord = &Tasks{}
	default:
		return false, fmt.Errorf("invalid table name: %s", tableName)
	}
	//column := database.NamingStrategy.ColumnName("", columnName)
	if err := database.Where(fmt.Sprintf("%s = ?", columnName), data).First(existingRecord).Error; err == nil {
		// 如果已存在相同的数据，则返回 true
		return true, nil
	} else if err != gorm.ErrRecordNotFound {
		// 如果查询时发生错误，则返回错误
		return false, fmt.Errorf("failed to query %s record: %v", tableName, err)
	}

	return false, nil
}

func DBCompaniesToStruct() error {
	db := GetDB()
	if db == nil {
		gologger.Info().Msg("获取数据库连接失败")
	}
	// 查询数据库中所有的公司信息
	var companies []Company
	if err := db.Find(&companies).Error; err != nil {
		return err
	}
	if len(companies) != 0 {
		// 将查询结果存储到 map 中
		for _, company := range companies {
			taskstruct.CompanyID[company.Name] = company.ID
		}
	}
	return nil
}

// CheckAllWorkflowStatus 返回是否已经没有workflow在任务中
func CheckAllWorkflowStatus(status string) bool {
	var workflow []Workflows
	database := GetDB()
	defer CloseDB(database)
	if database == nil {
		gologger.Error().Msg("Failed to get database connection")
	}
	// 查询整个表
	result := database.Where("Status != ?", status).Find(&workflow)
	if result.Error != nil {
		gologger.Error().Msg("查询workflow状态失败")
		return false
	}
	return result.RowsAffected == 0
}

// CheckAllTasksStatus 返回是否已经没有tasks
func CheckAllTasksStatus(status string) (bool, int) {
	var Taskslist []Tasks
	database := GetDB()
	defer CloseDB(database)
	if database == nil {
		gologger.Error().Msg("Failed to get database connection")
	}
	// 查询整个表
	result := database.Where("Status != ?", status).Find(&Taskslist)
	if result.Error != nil {
		gologger.Error().Msg("查询workflow状态失败")
		return false, 0
	}
	getwaitips, err := GetAllIPs("Completed", false)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	getwaitdomain, err := GetAllDomains("Completed", false)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	getwaittargets, err := GetTargets("Completed", false)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	return result.RowsAffected == 0 && len(getwaittargets) == 0 && len(getwaitdomain) == 0 && len(getwaitips) == 0, int(result.RowsAffected)
}

// 从target.yaml中写入公司到DB
func YamlCompanyToDB(targetconfig *taskstruct.Targetconfig) {
	db := GetDB()
	if db == nil {
		gologger.Info().Msg("获取数据库连接失败")
	}
	defer CloseDB(db)
	for _, target := range targetconfig.Target.Name {
		//判断数据库中是否已经存在
		exists, err := CheckDuplicateRecord(db, "Company", "Name", target)
		if err != nil {
			gologger.Info().Msg(err.Error())
		}
		if exists {
			continue
		}
		id, err := GetNextID(db, "companies")
		if err != nil {
			gologger.Error().Msg(err.Error())
			continue
		}
		Company := Company{
			ID:   id,
			Name: target,
		}
		err = WriteToCompany(db, Company)
		if err != nil {
			gologger.Error().Msg(err.Error())
			continue
		}
		taskstruct.CompanyID[target] = id
	}
}
