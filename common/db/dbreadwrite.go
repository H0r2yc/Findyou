package db

import (
	"github.com/projectdiscovery/gologger"
	"reflect"
)

func ItemTODB(dbdatas, dbdatas2, dbdatas3, dbdatas4 DBdata) error {
	var records []interface{} // 将记录保存到切片中
	// 创建数据库连接
	database := GetDB()
	for i := 0; i < len(dbdatas.Data); {
		data := dbdatas.Data[i]
		if database == nil {
			gologger.Error().Msg("Failed to get database connection")
			i++
			continue // 继续下一次循环
		}
		if dbdatas.Sole {
			isexists, err := CheckDuplicateRecord(database, dbdatas.TableName, dbdatas.Columnname, data)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			if isexists {
				// 如果记录已存在，删除相应的数据
				removeFromDBdata(&dbdatas, i)
				removeFromDBdata(&dbdatas2, i)
				removeFromDBdata(&dbdatas3, i)
				removeFromDBdata(&dbdatas4, i)
				continue // 继续下一次循环
			}
		}
		//如果没有删除记录，那么就+1
		i++
	}
	// 根据目标表格名称和字段名称创建对应的记录
	var record interface{}
	switch dbdatas.TableName {
	case "Company":
		record = &Company{}
	case "Domain":
		record = &Domain{}
	case "IPs":
		record = &IPs{}
	case "Fingerprint":
		record = &Fingerprint{}
	case "Targets":
		record = &Targets{}
	case "URLs":
		record = &URLs{}
	case "SearchKeywords":
		record = &SearchKeywords{}
	}
	//判断写入的数量以及写入的类型为string还是uint并写入到record
	records = getrecord(record, dbdatas, dbdatas2, dbdatas3, dbdatas4)
	// 保存记录到数据库
	for _, recorded := range records {
		if err := database.Create(recorded).Error; err != nil {
			gologger.Error().Msgf("Failed to create %s record: %v\n", dbdatas.TableName, err)
		}
	}
	return nil
}

func getrecord(record interface{}, dbdatas, dbdatas2, dbdatas3, dbdatas4 DBdata) []interface{} {
	var records []interface{}
	//获取最大id值
	db := getDB()
	maxid, err := GetNextTargetID(db)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	// 遍历数据，逐个设置字段值
	for i := 0; i < len(dbdatas.Data); i++ {
		// 创建一个新的结构体实例
		newRecord := reflect.New(reflect.TypeOf(record).Elem()).Interface()
		//设置ID值
		reflect.ValueOf(newRecord).Elem().FieldByName("ID").SetUint(uint64(int(maxid) + i))
		if dbdatas.ColumnLen == 1 {
			if dbdatas.Uint {
				setFieldValueUint(newRecord, dbdatas.Columnname, dbdatas.DataUint[i])
			} else {
				setFieldValue(newRecord, dbdatas.Columnname, dbdatas.Data[i])
			}
		} else if dbdatas.ColumnLen == 2 {
			if dbdatas.Uint {
				setFieldValueUint(newRecord, dbdatas.Columnname, dbdatas.DataUint[i])
			} else {
				setFieldValue(newRecord, dbdatas.Columnname, dbdatas.Data[i])
			}
			if dbdatas2.Uint {
				setFieldValueUint(newRecord, dbdatas2.Columnname, dbdatas2.DataUint[i])
			} else {
				setFieldValue(newRecord, dbdatas2.Columnname, dbdatas2.Data[i])
			}
		} else if dbdatas.ColumnLen == 3 {
			if dbdatas.Uint {
				setFieldValueUint(newRecord, dbdatas.Columnname, dbdatas.DataUint[i])
			} else {
				setFieldValue(newRecord, dbdatas.Columnname, dbdatas.Data[i])
			}
			if dbdatas2.Uint {
				setFieldValueUint(newRecord, dbdatas2.Columnname, dbdatas2.DataUint[i])
			} else {
				setFieldValue(newRecord, dbdatas2.Columnname, dbdatas2.Data[i])
			}
			if dbdatas3.Uint {
				setFieldValueUint(newRecord, dbdatas3.Columnname, dbdatas3.DataUint[i])
			} else {
				setFieldValue(newRecord, dbdatas3.Columnname, dbdatas3.Data[i])
			}
		} else if dbdatas.ColumnLen == 4 {
			if dbdatas.Uint {
				setFieldValueUint(newRecord, dbdatas.Columnname, dbdatas.DataUint[i])
			} else {
				setFieldValue(newRecord, dbdatas.Columnname, dbdatas.Data[i])
			}
			if dbdatas2.Uint {
				setFieldValueUint(newRecord, dbdatas2.Columnname, dbdatas2.DataUint[i])
			} else {
				setFieldValue(newRecord, dbdatas2.Columnname, dbdatas2.Data[i])
			}
			if dbdatas3.Uint {
				setFieldValueUint(newRecord, dbdatas3.Columnname, dbdatas3.DataUint[i])
			} else {
				setFieldValue(newRecord, dbdatas3.Columnname, dbdatas3.Data[i])
			}
			if dbdatas4.Uint {
				setFieldValueUint(newRecord, dbdatas4.Columnname, dbdatas4.DataUint[i])
			} else {
				setFieldValue(newRecord, dbdatas4.Columnname, dbdatas4.Data[i])
			}
		}
		// 将新的记录追加到切片中
		records = append(records, newRecord)
	}
	return records
}

// 从DBdata中移除索引为index的数据
func removeFromDBdata(dbdata *DBdata, index int) {
	if dbdata == nil {
		return
	}
	if index < 0 || index >= len(dbdata.Data) {
		return
	}
	if len(dbdata.Data) != 0 {
		dbdata.Data = append(dbdata.Data[:index], dbdata.Data[index+1:]...)
	} else if len(dbdata.DataUint) != 0 {
		dbdata.DataUint = append(dbdata.DataUint[:index], dbdata.DataUint[index+1:]...)
	}
}

// GetAllIPs 返回所有 IPs 表中的 ID 和 IP
func GetAllIPs() ([]string, error) {
	var ips []IPs
	database := GetDB()
	if database == nil {
		gologger.Error().Msg("Failed to get database connection")
	}
	// 查询整个表
	result := database.Model(&IPs{}).Find(&ips)
	if result.Error != nil {
		return nil, result.Error
	}

	//var idStrings []string
	var ipStrings []string
	for _, ip := range ips {
		//idStrings = append(idStrings, strconv.FormatUint(uint64(ip.ID), 10))
		ipStrings = append(ipStrings, ip.IP)
	}

	//return idStrings, ipStrings, nil
	return ipStrings, nil
}

// GetAllDomains 返回所有 IPs 表中的 ID 和 IP
func GetAllDomains() ([]string, error) {
	var domains []Domain
	database := GetDB()
	if database == nil {
		gologger.Error().Msg("Failed to get database connection")
	}
	// 查询整个表
	result := database.Model(&Domain{}).Find(&domains)
	if result.Error != nil {
		return nil, result.Error
	}

	//var idStrings []string
	var domainStrings []string
	for _, domain := range domains {
		//idStrings = append(idStrings, strconv.FormatUint(uint64(ip.ID), 10))
		domainStrings = append(domainStrings, domain.Domain)
	}

	//return idStrings, ipStrings, nil
	return domainStrings, nil
}

// GetAllTargets 从数据库中取出所有 Status 为 0 的数据
func GetAllTargets(status uint) ([]Targets, error) {
	db := getDB()
	var targets []Targets
	result := db.Where("Status = ?", status).Find(&targets)
	if result.Error != nil {
		return nil, result.Error
	}
	return targets, nil
}

// ProcessTargets 处理从数据库中取出的数据，并将 Status 设置为 1
func ProcessTargets(target *Targets, Title string, status uint) error {
	db := getDB()
	// 处理 targets
	// 设置 Status 为 1
	if err := db.Model(target).Updates(map[string]interface{}{"Status": status, "Title": Title}).Error; err != nil {
		return err
	}
	return nil
}
