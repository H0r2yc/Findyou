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

/*
Waiting(等待下一步):表示等待下一步操作的数据，比如加载到redis中
Pending（等待处理）：表示待处理的数据，还未开始处理。
Processing（处理中）：表示正在处理的数据，处理过程尚未完成。
Completed（已完成）：表示处理完成的数据，已经完成了所需的操作。
Failed（失败）：表示处理失败的数据，处理过程中出现了错误。
Cancelled（已取消）：表示已经取消处理的数据，可能是由于某种原因中止了处理过程。
Paused（已暂停）
*/

// 定义数据库模型
type Company struct {
	ID     uint `gorm:"primaryKey"`
	Name   string
	URLs   []URLs
	Status uint
}

type Domains struct {
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

type Fingerprints struct {
	ID          uint `gorm:"primaryKey"`
	Url         string
	Fingerprint string
	Status      uint
}

type Targets struct {
	ID     uint `gorm:"primaryKey"`
	Target string
	Title  string
	Status uint
}

type URLs struct {
	ID        uint `gorm:"primaryKey"`
	CompanyID uint // 外键，指向 Company 表中的记录
	Url       string
	Status    uint
}

type Keywords struct {
	ID      uint `gorm:"primaryKey"`
	Keyword string
	Count   uint
	Status  uint
}
