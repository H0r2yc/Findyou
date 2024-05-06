package onlineengine

import (
	"Findyou/common/config"
	"Findyou/common/db"
	"github.com/projectdiscovery/gologger"
)

func targetsToDB(result config.Targets) error {
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
	//创建一个和ips相同数量的Status值并赋值0
	StatusList := make([]uint, len(result.Targets))
	for i := 0; i < len(result.Targets); i++ {
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
	return nil
}

func DomainIPMapToDB(result config.Targets) error {
	//创建一个和ips相同数量的Status值并赋值0
	StatusList := make([]uint, len(result.Domains))
	for i := 0; i < len(result.Targets); i++ {
		StatusList[i] = 0
	}
	DomainStatus := db.DBdata{DataUint: StatusList, Columnname: "Status", Uint: true}
	//domain写入到Domain表
	Domain := db.DBdata{
		TableName:  "Domains",
		Columnname: "Domain",
		ColumnLen:  2,
		Sole:       true,
		Data:       result.Domains,
	}
	err := db.ItemTODB(Domain, DomainStatus, nildbdatas, nildbdatas)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	return nil
}

func KeywordsToDB(keywords config.SearchKeyWords) error {
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
