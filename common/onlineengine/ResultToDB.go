package onlineengine

import (
	"Findyou/common/config"
	"Findyou/common/db"
	"Findyou/common/utils"
	"github.com/projectdiscovery/gologger"
)

// TODO 写入类型全改成结构体
func targetsToDB(result config.Targets) error {
	if result.Targets == nil {
		return nil
	}
	//创建一个和ips及target相同数量的Status值并赋值0
	StatusList := make([]uint, len(result.Targets))
	for i := 0; i < len(result.Targets); i++ {
		StatusList[i] = 0
	}
	targetStatus := db.DBdata{DataUint: StatusList, Columnname: "Status", Uint: true}
	//所有target写入到targets表格
	targetdbdata := db.DBdata{
		TableName:  "Targets",
		Columnname: "Target",
		ColumnLen:  2,
		Sole:       true,
		Data:       result.Targets,
	}
	err := db.ItemTODB(targetdbdata, targetStatus, nildbdatas, nildbdatas)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	return nil
}

func IpsToDB(result config.Targets) error {
	if result.IPs == nil {
		return nil
	}
	//创建一个和ips相同数量的Status值并赋值0
	StatusList := make([]uint, len(result.IPs))
	for i := 0; i < len(result.IPs); i++ {
		StatusList[i] = 0
	}
	targetStatus := db.DBdata{DataUint: StatusList, Columnname: "Status", Uint: true}
	//ip写入到IPS表
	ipdbdata := db.DBdata{
		TableName:  "IPs",
		Columnname: "IP",
		ColumnLen:  2,
		Sole:       true,
		Data:       result.IPs,
	}
	err := db.ItemTODB(ipdbdata, targetStatus, nildbdatas, nildbdatas)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	return nil
}

func DomainsToDB(result config.Targets) error {
	if result.Domains == nil {
		return nil
	}
	//创建一个和ips相同数量的Status值并赋值0
	StatusList := make([]uint, len(result.Domains))
	for i := 0; i < len(result.Domains); i++ {
		StatusList[i] = 0
	}
	DomainIPs := db.DBdata{Data: result.DomainIps, Columnname: "IP"}
	DomainIsCDNs := db.DBdata{DataUint: result.IsCDN, Columnname: "ISCdn", Uint: true}
	DomainStatus := db.DBdata{DataUint: StatusList, Columnname: "Status", Uint: true}
	//domain写入到Domain表
	Domain := db.DBdata{
		TableName:  "Domains",
		Columnname: "Domain",
		ColumnLen:  4,
		Sole:       true,
		Data:       result.Domains,
	}
	err := db.ItemTODB(Domain, DomainIPs, DomainIsCDNs, DomainStatus)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	//不是cdn的ip写入到ips表中并初始化，因为有cdn的为空，所以先去除空值
	result.DomainIps = utils.RemoveDuplicateElement(result.DomainIps)
	var newIPs []string
	for _, str := range result.DomainIps {
		if str != "" && !utils.StringInSlice(utils.GetCIDR(str), newIPs) {
			newIPs = append(newIPs, str)
		}
	}
	result.IPs = newIPs
	err = IpsToDB(result)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	return nil
}

func KeywordsToDB(keywords config.SearchKeyWords) error {
	if keywords.KeyWords == nil {
		return nil
	}
	//创建一个和ips及target相同数量的Status值并赋值0
	KeywordStatus := db.DBdata{DataUint: keywords.SearchStatus, Columnname: "Status", Uint: true}
	KeywordCount := db.DBdata{DataUint: keywords.SearchCount, Columnname: "Count", Uint: true}
	//所有target写入到targets表格
	Keyworddbdata := db.DBdata{
		TableName:  "Keywords",
		Columnname: "Keyword",
		ColumnLen:  3,
		Sole:       true,
		Data:       keywords.KeyWords,
	}
	err := db.ItemTODB(Keyworddbdata, KeywordCount, KeywordStatus, nildbdatas)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	return nil
}

func KeywordToDB(KeyWord string, result config.Targets) error {
	//TODO 失败写入err内容
	if KeyWord == "" {
		return nil
	}
	//创建一个和ips及target相同数量的Status值并赋值0
	KeywordStatus := db.DBdata{DataUint: []uint{result.SearchStatus}, Columnname: "Status", Uint: true}
	KeywordCount := db.DBdata{DataUint: []uint{result.SearchCount}, Columnname: "Count", Uint: true}
	//所有target写入到targets表格
	Keyworddbdata := db.DBdata{
		TableName:  "Keywords",
		Columnname: "Keyword",
		ColumnLen:  3,
		Sole:       true,
		Data:       []string{KeyWord},
	}
	err := db.ItemTODB(Keyworddbdata, KeywordCount, KeywordStatus, nildbdatas)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	return nil
}
