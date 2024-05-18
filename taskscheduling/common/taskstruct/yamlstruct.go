package taskstruct

type Targetconfig struct {
	Target          Target          `yaml:"目标"`
	Customizesyntax customizesyntax `yaml:"自定义扫描"`
	OtherSet        OtherSet        `yaml:"其他扫描选项"`
}

type Appconfig struct {
	API       API       `yaml:"api"`
	OnlineAPI OnlineAPI `yaml:"onlineapi"`
	Splittodb Splittodb `yaml:"splittodb"`
	Mysql     Mysql     `yaml:"mysql"`
	Redis     Redis     `yaml:"redis"`
}

type Splittodb struct {
	Fofakeyword   int `yaml:"fofakeyword"`
	Hunterkeyword int `yaml:"hunterkeyword"`
	Quakekeyword  int `yaml:"quakekeyword"`
	Workflow      int `yaml:"targets"`
}

type OtherSet struct {
	DBScan bool `yaml:"跳过配置从数据库扫描"`
}

type API struct {
	SearchPageSize   int    `yaml:"searchPageSize"`
	SearchLimitCount int    `yaml:"searchLimitCount"`
	Fofa             APIKey `yaml:"fofa"`
	ICP              APIKey `yaml:"icp"`
	Quake            APIKey `yaml:"quake"`
	Hunter           APIKey `yaml:"hunter"`
}

type APIKey struct {
	Key string `yaml:"key"`
}

type Target struct {
	Name           []string `yaml:"名称"`
	Domain         []string `yaml:"域名"`
	IP             []string `yaml:"ip"`
	Cert           []string `yaml:"cert"`
	City           []string `yaml:"city"`
	Gobal_keywords []string `yaml:"gobal_keyword"`
}

type customizesyntax struct {
	Fofa        []string `yaml:"fofa"`
	Hunter      []string `yaml:"hunter"`
	Quake       []string `yaml:"quake"`
	SearchLevel int      `yaml:"递归搜索等级"`
}

type OnlineAPI struct {
	Fofa   bool `yaml:"fofa"`
	Quake  bool `yaml:"quake"`
	Hunter bool `yaml:"hunter"`
}

type Mysql struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Dbname   string `yaml:"name"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Redis struct {
	Host     string `yaml:"host"`
	Password string `yaml:"password"`
}
