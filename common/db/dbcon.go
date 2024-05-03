package db

import (
	"Findyou/common/config"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"strings"
	"time"
)

var globalDB *gorm.DB

func GetDB() *gorm.DB {
	if globalDB != nil {
		return globalDB
	}
	const MAXRETRYNUMBER = 5
	const RetriedSleepTime = 5 * time.Second
	RetriedCount := 0
	for {
		if RetriedCount > MAXRETRYNUMBER {
			log.Println("Failed to connect database")
			return nil
		}
		globalDB = getDB()
		if globalDB == nil {
			log.Println("connect to database fail,retry...")
			RetriedCount++
			time.Sleep(RetriedSleepTime)
			continue
		}
		return globalDB
	}
}

func getDB() *gorm.DB {
	database := config.GetAppConf().Database
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		database.Username, database.Password, database.Host, database.Port, database.Dbname)

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		gologger.Error().Msgf(err.Error())
		if strings.Contains(err.Error(), "Unknown database 'findyou'") {
			dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/?charset=utf8mb4&parseTime=True&loc=Local",
				database.Username, database.Password, database.Host, database.Port)

			db2, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			checkDatabaseAndTables(db2)
		}
		return nil
	}
	//当没有开启debug模式的时候，gorm底层默认的log级别是Warn，
	//当SQL语句执行时间超过了100ms的时候就会触发Warn日志打印，同时错误的SQL语句也会触发。
	//设置为Silent后将不会显示任何SQL语句
	db.Logger = logger.Default.LogMode(logger.Silent)

	//设置连接池参数
	sqlDB, _ := db.DB()
	sqlDB.SetMaxIdleConns(10)
	// SetMaxOpenConns sets the maximum number of open connections to the database.
	sqlDB.SetMaxOpenConns(100)
	// SetConnMaxLifetime sets the maximum amount of time a connection may be reused.
	sqlDB.SetConnMaxLifetime(time.Hour)

	return db
}

// CloseDB 显式关闭一个数据库连接
func CloseDB(db *gorm.DB) {
	//全局长连接模式不能关闭数据库连接
	//sql, _ := db.DB()
	//defer sql.Close()
	return
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
	}

	// 使用 Findyou 数据库
	db.Exec("USE Findyou")

	// 检查表格是否存在，如果不存在则执行迁移
	if err := db.AutoMigrate(&Company{}, &Domain{}, &IPs{}, &Fingerprint{}, &Targets{}, &URLs{}, &SearchKeywords{}); err != nil {
		return fmt.Errorf("failed to migrate tables: %w", err)
	}

	gologger.Info().Msg("数据库和表格创建完成！")
	return nil
}
