package workflowstruct

type Appconfig struct {
	API         API         `yaml:"api"`
	Portscan    Portscan    `yaml:"portscan"`
	Fingerprint Fingerprint `yaml:"fingerprint"`
	//Domainscan   Domainscan  `yaml:"domainscan"`
	Proxy        Proxy     `yaml:"proxy"`
	OnlineAPI    OnlineAPI `yaml:"onlineapi"`
	Mysql        Mysql     `yaml:"mysql"`
	Redis        Redis     `yaml:"redis"`
	CDNConfig    CDNConfig `yaml:"cdnconfig"`
	Httpxconfig  Httpx     `yaml:"httpx"`
	Nucleiconfig Nuclei    `yaml:"nuclei"`
}

type OnlineAPI struct {
	IsFofa   bool `yaml:"fofa"`
	IsQuake  bool `yaml:"quake"`
	IsHunter bool `yaml:"hunter"`
}

type Nuclei struct {
	Threads int `yaml:"Threads"`
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
	CDNBruteForceThreads int `yaml:"threads"`
}

type APIKey struct {
	Key string `yaml:"key"`
}

type Portscan struct {
	IsPing bool   `yaml:"ping"`
	Port   string `yaml:"port"`
	Rate   int    `yaml:"rate"`
	Tech   string `yaml:"tech"`
	Cmdbin string `yaml:"cmdbin"`
}

type Fingerprint struct {
	IsDirsearch      bool     `yaml:"dirsearch"`
	IsScreenshot     bool     `yaml:"screenshot"`
	IsFingerprintHub bool     `yaml:"fingerprinthub"`
	IsIconHash       bool     `yaml:"iconhash"`
	IsFingerprintx   bool     `yaml:"fingerprintx"`
	CustomDir        []string `yaml:"customdir"`
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
