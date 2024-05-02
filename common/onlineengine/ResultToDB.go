package onlineengine

import (
	"Findyou/common/config"
	"Findyou/common/db"
	"github.com/projectdiscovery/gologger"
)

func targetsToDB(result config.Targets) error {
	//创建一个和ips及target相同数量的isdone值并赋值0
	IsdoneList := make([]uint, len(result.Targets))
	for i := 0; i < len(result.Targets); i++ {
		IsdoneList[i] = 0
	}
	targetIsdone := db.DBdata{DataUint: IsdoneList, Columnname: "Isdone", Uint: true}
	//所有target写入到targets表格
	targetdbdata := db.DBdata{
		TableName:  "Targets",
		Columnname: "Target",
		ColumnLen:  2,
		Sole:       true,
		Data:       result.Targets,
	}
	err := db.ItemTODB(targetdbdata, targetIsdone, nildbdatas, nildbdatas)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	return nil
}

func IpsToDB(result config.Targets) error {
	//创建一个和ips相同数量的isdone值并赋值0
	IsdoneList := make([]uint, len(result.Targets))
	for i := 0; i < len(result.Targets); i++ {
		IsdoneList[i] = 0
	}
	targetIsdone := db.DBdata{DataUint: IsdoneList, Columnname: "Isdone", Uint: true}
	//ip写入到IPS表
	ipdbdata := db.DBdata{
		TableName:  "IPs",
		Columnname: "IP",
		ColumnLen:  2,
		Sole:       true,
		Data:       result.IPs,
	}
	err := db.ItemTODB(ipdbdata, targetIsdone, nildbdatas, nildbdatas)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	return nil
}

func DomainsToDB(result config.Targets) error {
	//创建一个和ips相同数量的isdone值并赋值0
	IsdoneList := make([]uint, len(result.Domains))
	for i := 0; i < len(result.Domains); i++ {
		IsdoneList[i] = 0
	}
	DomainIsdone := db.DBdata{DataUint: IsdoneList, Columnname: "Isdone", Uint: true}
	//domain写入到Domain表
	Domain := db.DBdata{
		TableName:  "Domain",
		Columnname: "Domain",
		ColumnLen:  2,
		Sole:       true,
		Data:       result.Domains,
	}
	err := db.ItemTODB(Domain, DomainIsdone, nildbdatas, nildbdatas)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	return nil
}

func DomainIPMapToDB(result config.Targets) error {
	//创建一个和ips相同数量的isdone值并赋值0
	IsdoneList := make([]uint, len(result.Domains))
	for i := 0; i < len(result.Targets); i++ {
		IsdoneList[i] = 0
	}
	DomainIsdone := db.DBdata{DataUint: IsdoneList, Columnname: "Isdone", Uint: true}
	//domain写入到Domain表
	Domain := db.DBdata{
		TableName:  "Domain",
		Columnname: "Domain",
		ColumnLen:  2,
		Sole:       true,
		Data:       result.Domains,
	}
	err := db.ItemTODB(Domain, DomainIsdone, nildbdatas, nildbdatas)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	return nil
}
