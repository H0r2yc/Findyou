package config

type Targetcofig struct {
	Ips             []string
	Target          Target          `yaml:"目标"`
	Customizesyntax customizesyntax `yaml:"自定义语法扫描"`
	Pocset          PocSet          `yaml:"poc扫描"`
}

type Appconfig struct {
	//Rpc         RPC         `yaml:"rpc"`
	//FileSync    RPC         `yaml:"fileSync"`
	//Rabbitmq    Rabbitmq    `yaml:"rabbitmq"`
	API         API         `yaml:"api"`
	Portscan    Portscan    `yaml:"portscan"`
	Fingerprint Fingerprint `yaml:"fingerprint"`
	Domainscan  Domainscan  `yaml:"domainscan"`
	OnlineAPI   OnlineAPI   `yaml:"onlineapi"`
	Pocscan     Pocscan     `yaml:"pocscan"`
	Proxy       Proxy       `yaml:"proxy"`
	Database    Database    `yaml:"database"`
	CDNConfig   CDNConfig   `yaml:"cdnconfig"`
	Httpxconfig Httpx       `yaml:"httpx"`
}

type PocSet struct {
	Enable           bool   `yaml:"启用"`
	PocNameForSearch string `yaml:"指定漏洞"`
}

type Httpx struct {
	HTTPProxy  string `yaml:"HTTPProxy"`
	WebThreads int    `yaml:"WebThreads"`
	WebTimeout int    `yaml:"WebTimeout"`
}

type API struct {
	SearchPageSize   int    `yaml:"searchPageSize"`
	SearchLimitCount int    `yaml:"searchLimitCount"`
	Fofa             APIKey `yaml:"fofa"`
	ICP              APIKey `yaml:"icp"`
	Quake            APIKey `yaml:"quake"`
	Hunter           APIKey `yaml:"hunter"`
}

type CDNConfig struct {
	SubdomainBruteForceThreads int `yaml:"threads"`
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

type AQCQCC struct {
	Percent      int  `yaml:"占股子公司比例"`
	IsSearchNext bool `yaml:"全资控股公司是否递归查找"`
	Level        int  `yaml:"递归等级"`
}

type customizesyntax struct {
	Fofa   []string `yaml:"fofa"`
	Hunter []string `yaml:"hunter"`
	Quake  []string `yaml:"quake"`
}

type OnlineAPI struct {
	IsFofa   bool `yaml:"fofa"`
	IsQuake  bool `yaml:"quake"`
	IsHunter bool `yaml:"hunter"`
}

type Portscan struct {
	IsPing bool   `yaml:"ping"`
	Port   string `yaml:"port"`
	Rate   int    `yaml:"rate"`
	Tech   string `yaml:"tech"`
	Cmdbin string `yaml:"cmdbin"`
}

type Fingerprint struct {
	IsHttpx          bool `yaml:"httpx"`
	IsScreenshot     bool `yaml:"screenshot"`
	IsFingerprintHub bool `yaml:"fingerprinthub"`
	IsIconHash       bool `yaml:"iconhash"`
	IsFingerprintx   bool `yaml:"fingerprintx"`
}

type Database struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Dbname   string `yaml:"name"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Pocscan struct {
	Xray struct {
		PocPath string `yaml:"pocPath"`
	} `yaml:"xray"`
	Nuclei struct {
		PocPath string `yaml:"pocPath"`
	} `yaml:"nuclei"`
	Goby struct {
		AuthUser string   `yaml:"authUser"`
		AuthPass string   `yaml:"authPass"`
		API      []string `yaml:"api"`
	} `yaml:"goby"`
}

type Domainscan struct {
	Resolver           string `yaml:"resolver"`
	Wordlist           string `yaml:"wordlist"`
	ProviderConfig     string `yaml:"providerConfig"`
	IsSubDomainFinder  bool   `yaml:"subfinder"`
	IsSubDomainBrute   bool   `yaml:"subdomainBrute"`
	IsSubdomainCrawler bool   `yaml:"subdomainCrawler"`
	IsIgnoreCDN        bool   `yaml:"ignoreCDN"`
	IsIgnoreOutofChina bool   `yaml:"ignoreOutofChina"`
	IsPortScan         bool   `yaml:"portscan"`
	IsWhois            bool   `yaml:"whois"`
	IsICP              bool   `yaml:"icp"`
}

type Proxy struct {
	Host []string `yaml:"host"`
}
