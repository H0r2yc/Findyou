package mysqldb

import (
	"Findyou.WorkFlow/common/utils"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"golang.org/x/net/publicsuffix"
	"gorm.io/gorm"
	"strings"
	"sync"
)

var mysqllock sync.Mutex

func TargetsToDB(TargetList []string, companyid, taskid uint) error {
	if len(TargetList) == 0 {
		return nil
	}
	database := GetDB()
	if database == nil {
		gologger.Error().Msg("获取数据库连接失败")
	}
	defer CloseDB(database)
	for _, target := range TargetList {
		isexists, err := CheckDuplicateRecord(database, "Targets", "Target", target)
		if isexists {
			continue
		}
		targetdb := Targets{
			Target:    target,
			CompanyID: companyid,
			TaskID:    taskid,
			Status:    "Waiting",
		}
		err = WriteToTargets(database, targetdb)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}
	return nil
}

func IpsToDB(ips []string, companyid uint) error {
	if len(ips) == 0 {
		return nil
	}
	database := GetDB()
	if database == nil {
		gologger.Error().Msg("获取数据库连接失败")
	}
	defer CloseDB(database)
	//创建一个和ips相同数量的Status值并赋值0
	for _, ip := range ips {
		isexists, err := CheckDuplicateRecord(database, "IPs", "IP", ip)
		if isexists {
			continue
		}
		ipsdb := IPs{
			IP:        ip,
			CompanyID: companyid,
			Status:    "Waiting",
		}
		err = WriteToIPs(database, ipsdb)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}
	return nil
}

func DomainsToDB(domains []string, domainsip map[string][]string, companyid uint) error {
	if len(domains) == 0 {
		return nil
	}
	database := GetDB()
	if database == nil {
		gologger.Error().Msg("获取数据库连接失败")
	}
	defer CloseDB(database)
	for _, domain := range domains {
		isexists, err := CheckDuplicateRecord(database, "Domains", "Domain", domain)
		if isexists {
			continue
		}
		rootdomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		iscdn := len(domainsip[domain]) == 0
		domainsdb := Domains{
			Domain:     domain,
			IP:         strings.Join(domainsip[domain], ","),
			ISCdn:      iscdn,
			CompanyID:  companyid,
			RootDomain: rootdomain,
			Status:     "Waiting",
		}
		err = WriteToDomains(database, domainsdb)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}
	//不是cdn的ip写入到ips表中并初始化，因为有cdn的为空，所以先去除空值
	var allip []string
	for _, ips := range domainsip {
		allip = append(allip, ips...)
	}
	allip = utils.RemoveDuplicateElement(allip)
	var newIPs []string
	for _, str := range allip {
		if str != "" && !utils.StringInSlice(utils.GetCIDR(str), newIPs) {
			newIPs = append(newIPs, str)
		}
	}
	err := IpsToDB(newIPs, companyid)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	return nil
}

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
	case "HighLevelTargets":
		existingRecord = &HighLevelTargets{}
	case "Targets":
		existingRecord = &Targets{}
	case "SensitiveInfo":
		existingRecord = &SensitiveInfo{}
	case "Keywords":
		existingRecord = &Keywords{}
	case "Workflows":
		existingRecord = &Workflows{}
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

func SensitiveInfoToDB(Url, PhoneNum, Supplychain, ICP string) error {
	database := GetDB()
	if database == nil {
		gologger.Error().Msg("获取数据库连接失败")
	}
	mysqllock.Lock()
	defer mysqllock.Unlock()
	SensitiveInfostruct := SensitiveInfo{
		Url:         Url,
		PhoneNum:    PhoneNum,
		Supplychain: Supplychain,
		ICP:         ICP,
	}
	err := WriteToSensitiveInfo(database, SensitiveInfostruct)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	return err
}

func HighLevelTargetsToDB(highlevellist []HighLevelTargets) error {
	database := GetDB()
	for _, highleveltarget := range highlevellist {
		err := WriteToHighLevelTargets(database, highleveltarget)
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}
	return nil
}
