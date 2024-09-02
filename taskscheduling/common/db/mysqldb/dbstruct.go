package mysqldb

/*
Waiting(等待下一步):表示等待下一步操作的数据，比如加载到redis中
Pending（等待处理）：表示待处理的数据，还未开始处理。
Processing（处理中）：表示正在处理的数据，处理过程尚未完成。
Completed（已完成）：表示处理完成的数据，已经完成了所需的操作。
Failed（失败）：表示处理失败的数据，处理过程中出现了错误。
Cancelled（已取消）：表示已经取消处理的数据，可能是由于某种原因中止了处理过程。
FingerComplete
Paused（已暂停）
*/

//使用Redis的键值对
//FOFASEARCH
//FOFADBSEARCH
//HUNTERSEARCH
//HUNTERDBSEARCH
//QUAKESEARCH
//QUAKEDBSEARCH
//DOMAINBRUTE
//ALIVEANDPASSIVITYSCAN
//AQCQCCSCAN
//FINGERPRINT

type KeywordsList struct {
	//keywords是为了第一次生成的时候用，后面db生成不再需要
	FofaKeyWords   []string
	FofaKeyWord    string
	HunterKeyWords []string
	QuakeKeyWords  string
}

// 定义数据库模型
type Company struct {
	ID   uint `gorm:"primaryKey"`
	Name string
}

type Domains struct {
	ID         uint `gorm:"primaryKey"`
	Domain     string
	IP         string
	ISCdn      bool
	CompanyID  uint
	RootDomain string
	Status     string
}

type IPs struct {
	ID        uint `gorm:"primaryKey"`
	IP        string
	CompanyID uint
	Status    string
}

type HighLevelTargets struct {
	ID        uint `gorm:"primaryKey"`
	Url       string
	Title     string
	Finger    string
	Priority  uint
	tags      string
	Vuln      string
	CompanyID uint
}

type Targets struct {
	ID          uint `gorm:"primaryKey"`
	Target      string
	Title       string
	FingerPrint string
	Priority    uint
	CompanyID   uint
	TaskID      uint
	Status      string
}

type SensitiveInfo struct {
	ID          uint `gorm:"primaryKey"`
	Url         string
	PhoneNum    string
	Supplychain string
	ICP         string
}

type Keywords struct {
	ID           uint `gorm:"primaryKey"`
	Onlineengine string
	Keyword      string
}

type Workflows struct {
	ID     uint `gorm:"primaryKey"`
	Status string
}

type Tasks struct {
	ID        uint `gorm:"primaryKey"`
	TaskName  string
	Task      string
	Count     uint
	CompanyID uint
	Status    string
	Note      string
}
