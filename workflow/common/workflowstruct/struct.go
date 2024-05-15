package workflowstruct

import (
	"embed"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"net"
	"sync"
)

// GlobalIPDomainMap 存储ip->domains的关系
var GlobalIPDomainMap map[string][]string
var GlobalIPDomainMapLock sync.Mutex

var Dirs map[string][]string
var Fingerprints []FingerPEntity

// GlobalURLMap RootURL:URLEntity
var GlobalURLMap map[string]URLEntity
var GlobalURLMapLock sync.Mutex

var GlobalHttpBodyHMap *hybrid.HybridMap
var GlobalHttpHeaderHMap *hybrid.HybridMap
var GlobalBannerHMap *hybrid.HybridMap
var WorkFlowDB map[string]WorkFlowEntity
var GlobalEmbedPocs embed.FS

// GlobalResultMap 存储识别到的指纹
var GlobalResultMap map[string][]string

type Targets struct {
	Targets   []string
	Domains   []string
	DomainIps []string
	IPs       []string
	//DomainIPMap     map[string][]string
	//DomainIPMapLock sync.Mutex
	IsCDN        []uint
	SearchCount  uint
	SearchStatus uint
}

type SearchKeyWords struct {
	KeyWords     []string
	SearchCount  []uint
	SearchStatus []uint
}

type WorkFlowEntity struct {
	RootType bool
	DirType  bool
	BaseType bool
	PocsName []string
}

type FingerPEntity struct {
	ProductName      string
	AllString        string
	Rule             []RuleData
	IsExposureDetect bool
}

type RuleData struct {
	Start int
	End   int
	Op    int16  // 0= 1!= 2== 3>= 4<= 5~=
	Key   string // body="123"中的body
	Value string // body="123"中的123
	All   string // body="123"
}

type URLEntity struct {
	IP       string
	Port     int
	WebPaths map[string]UrlPathEntity
	Cert     string // TLS证书
}

type UrlPathEntity struct {
	// Path             string // 根目录为/
	Hash             string // md5
	IconHash         string //mmh3
	Title            string
	StatusCode       int
	ContentType      string
	Server           string
	ContentLength    int
	HeaderHashString string
}

// -------------------------------------
const (
	TypeDomain     = 1
	TypeDomainPort = 2
	TypeIPRange    = 3
	TypeCIDR       = 4
	TypeIP         = 5
	TypeIPPort     = 6
	TypeURL        = 7
	TypeUnSupport  = 0
)

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
