package db

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
	Status uint
}

type Domain struct {
	ID     uint `gorm:"primaryKey"`
	Domain string
	IP     string
	ISCdn  uint
	Status uint
}

type IPs struct {
	ID     uint `gorm:"primaryKey"`
	IP     string
	Status uint
}

type Fingerprint struct {
	ID          uint `gorm:"primaryKey"`
	Company     string
	Fingerprint string
}

type Targets struct {
	ID     uint `gorm:"primaryKey"`
	Target string
	Status uint
}

type URLs struct {
	ID        uint `gorm:"primaryKey"`
	CompanyID uint // 外键，指向 Company 表中的记录
	Url       string
	Status    uint
}

type SearchKeywords struct {
	ID            uint `gorm:"primaryKey"`
	SearchKeyword string
	Count         uint
	Status        uint
}
