package mysqldb

import (
	"Findyou.TaskScheduling/common/taskstruct"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"strings"
)

func CheckAndCreate(appconfig *taskstruct.Appconfig) {
	database := appconfig.Mysql
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/?charset=utf8mb4&parseTime=True&loc=Local",
		database.Username, database.Password, database.Host, database.Port)

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	err = checkDatabaseAndTables(db)
	defer CloseDB(db)
	if err != nil && strings.Contains(err.Error(), "database exists") {
		gologger.Info().Msg("数据库存在，使用现有数据库")
	}
}

// 检查数据库和表格是否存在，如果不存在则执行初始化操作
func checkDatabaseAndTables(db *gorm.DB) error {
	// 检查数据库是否存在
	var count int64
	if err := db.Raw("SELECT count(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?", "Findyou").Scan(&count).Error; err != nil {
		return fmt.Errorf("failed to check database existence: %w", err)
	}
	if count == 0 {
		// 如果数据库不存在，则创建数据库
		if err := db.Exec("CREATE DATABASE Findyou").Error; err != nil {
			return fmt.Errorf("failed to create database: %w", err)
		}
	} else {
		return fmt.Errorf("database exists")
	}

	// 使用 Findyou 数据库
	db.Exec("USE Findyou")

	// 检查表格是否存在，如果不存在则执行迁移
	if err := db.AutoMigrate(&Company{}, &Domains{}, &IPs{}, &HighLevelTargets{}, &Targets{}, &SensitiveInfo{}, &Keywords{}, &Workflows{}, &Tasks{}); err != nil {
		return fmt.Errorf("failed to migrate tables: %w", err)
	}

	gologger.Info().Msg("数据库和表格创建完成！")
	return nil
}
