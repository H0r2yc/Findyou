package db

type Dbtables struct {
	Company     Company
	Domain      Domain
	IP          IPs
	Fingerprint Fingerprint
	Targets     Targets
	URL         URLs
}

type DBdata struct {
	TableName  string
	ColumnLen  int
	Columnname string
	Uint       bool
	Sole       bool
	Data       []string
	DataUint   []uint
}

// 定义数据库模型
type Company struct {
	ID     uint `gorm:"primaryKey"`
	Name   string
	URLs   []URLs
	Isdone uint
}

type Domain struct {
	ID     uint `gorm:"primaryKey"`
	Domain string
	IP     string
	ISCdn  uint
	Isdone uint
}

type IPs struct {
	ID     uint `gorm:"primaryKey"`
	IP     string
	Isdone uint
}

type Fingerprint struct {
	ID          uint `gorm:"primaryKey"`
	Company     string
	Fingerprint string
}

type Targets struct {
	ID     uint `gorm:"primaryKey"`
	Target string
	Isdone uint
}

type URLs struct {
	ID        uint `gorm:"primaryKey"`
	CompanyID uint // 外键，指向 Company 表中的记录
	Url       string
	Isdone    uint
}

type Search struct {
	ID            uint `gorm:"primaryKey"`
	SearchKeyword string
	success       uint
}
