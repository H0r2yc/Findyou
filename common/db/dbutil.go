package db

import (
	"Findyou/common/utils"
	"fmt"
	"gorm.io/gorm"
	"reflect"
)

// setFieldValue 使用反射动态设置结构体字段的值
func setFieldValue(record interface{}, columnname string, data string) {
	// 获取结构体字段
	valueOf := reflect.ValueOf(record).Elem()
	field := valueOf.FieldByName(columnname)
	if field.IsValid() {
		// 如果字段有效，则设置字段值
		field.SetString(data)
	}
}

// setFieldValueUint 使用反射动态设置结构体字段的值
func setFieldValueUint(record interface{}, columnname string, data uint) {
	// 获取结构体字段
	valueOf := reflect.ValueOf(record).Elem()
	field := valueOf.FieldByName(columnname)
	if field.IsValid() {
		// 如果字段有效，则设置字段值
		field.SetUint(uint64(data))
	}
}

/*
func setFieldValue(record interface{}, records *[]interface{}, columnname string, datalist []string) {
	for _, data := range datalist {
		// 创建一个新的结构体实例
		newRecord := reflect.New(reflect.TypeOf(record).Elem()).Interface()
		// 获取结构体字段
		valueOf := reflect.ValueOf(newRecord).Elem()
		field := valueOf.FieldByName(columnname)
		if field.IsValid() {
			// 如果字段有效，则设置字段值
			field.SetString(data)
		}
		// 将新的记录追加到切片中
		*records = append(*records, newRecord)
	}
}
*/

func Isipclr(ip string) bool {
	var existingIPs []IPs
	ipc := utils.GetCIDR(ip)
	db := GetDB()
	db.Where("ip_address LIKE ?", ipc+"%").Find(&existingIPs)
	CloseDB(db)
	if len(existingIPs) > 0 {
		return true
	} else {
		return false
	}
}

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

func GetNextTargetID(db *gorm.DB, table string) (uint, error) {
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

func GetTargetID(targets []Targets, targetString string) (*Targets, error) {
	for _, target := range targets {
		if target.Target == targetString {
			return &target, nil // 如果找到匹配的目标字符串，返回相应的 ID
		}
	}
	return nil, fmt.Errorf("Target not found") // 如果未找到匹配的目标字符串，则返回错误
}
