package workflowstruct

import (
	"embed"
	"net"
)

var FingerPrints []Fingerprints
var ActiveFingerPrints []Fingerprints

type Fingerprints struct {
	Path           string            `yaml:"path"`
	RequestMethod  string            `yaml:"request_method"`
	RequestHeaders map[string]string `yaml:"request_headers"`
	RequestData    string            `yaml:"request_data"`
	StatusCode     int               `yaml:"status_code"`
	Headers        map[string]string `yaml:"headers"`
	Keyword        []string          `yaml:"keyword"`
	FaviconHash    []string          `yaml:"favicon_hash"`
	Priority       int               `yaml:"priority"`
	Name           string            `yaml:"name"`
}

type Urlentity struct {
	Url           string
	InputUrl      string
	Title         string
	ContentLength int
	Iconhash_md5  string
	Iconhash_mmh3 string
	Body          string
	StatusCode    int
	Header        map[string][]string
	Status        bool
}

var WorkFlowDB map[string]WorkFlowEntity
var GlobalEmbedPocs embed.FS

// GlobalResultMap 存储识别到的指纹
var GlobalResultMap map[string][]string

type Subdomains struct {
	Subdomains   []string
	SubdomainIPs map[string][]string
	IPs          []string
}

type Targets struct {
	Targets      []string
	Domains      []string
	DomainIps    map[string][]string
	IPs          []string
	SearchCount  uint
	SearchStatus uint
}

type WorkFlowEntity struct {
	RootType bool
	DirType  bool
	BaseType bool
	PocsName []string
}

type DDConfig struct {
	Targets                    []string
	Ports                      string
	NoSubdomainBruteForce      bool
	NoSubFinder                bool
	Subdomain                  bool
	SubdomainBruteForceThreads int
	SkipHostDiscovery          bool
	PortScanType               string
	GetBannerThreads           int
	GetBannerTimeout           int
	TCPPortScanThreads         int
	SYNPortScanThreads         int
	PortsThreshold             int
	TCPPortScanTimeout         int
	MasscanPath                string
	AllowLocalAreaDomain       bool
	AllowCDNAssets             bool
	NoHostBind                 bool
	SubdomainWordListFile      string
	HTTPProxy                  string
	HTTPProxyTest              bool
	HTTPProxyTestURL           string
	Hunter                     bool
	HunterPageSize             int
	HunterMaxPageCount         int
	Fofa                       bool
	FofaMaxCount               int
	NoDirSearch                bool
	DirSearchYaml              string
	NoGolangPoc                bool
	DisableGeneralPoc          bool
	NucleiTemplate             string
	ExcludeTags                string
	Severities                 string
	WorkflowYamlPath           string
	ReportName                 string
	GoPocThreads               int
	WebThreads                 int
	WebTimeout                 int
	PocNameForSearch           string
	NoPoc                      bool
	LowPerceptionMode          bool
	Quake                      bool
	QuakeSize                  int
	NoICMPPing                 bool
	TCPPing                    bool
	NoInteractsh               bool
	OnlyIPPort                 bool
	OutputFile                 string
	OutputType                 string
	APIConfigFilePath          string
	FingerConfigFilePath       string
	PasswordFile               string
	Password                   string
}

type CDNResult struct {
	Domain  string
	IsCDN   bool
	CDNName string
	IPs     []net.IP
}

var GlobalConfig DDConfig
