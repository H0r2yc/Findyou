package runner

import (
	"errors"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/projectdiscovery/goconfig"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	fileutil "github.com/projectdiscovery/utils/file"
	updateutils "github.com/projectdiscovery/utils/update"
)

const (
	DefaultResumeFile = "resume.cfg"
)

var PDCPApiKey string

type Options struct {
	Resolvers          string
	Hosts              string
	Domains            string
	WordList           string
	Threads            int
	RateLimit          int
	Retries            int
	OutputFormat       string
	OutputFile         string
	Raw                bool
	Silent             bool
	Verbose            bool
	Version            bool
	NoColor            bool
	Response           bool
	ResponseOnly       bool
	A                  bool
	AAAA               bool
	NS                 bool
	CNAME              bool
	PTR                bool
	MX                 bool
	SOA                bool
	ANY                bool
	TXT                bool
	SRV                bool
	AXFR               bool
	JSON               bool
	OmitRaw            bool
	Trace              bool
	TraceMaxRecursion  int
	WildcardThreshold  int
	WildcardDomain     string
	ShowStatistics     bool
	rcodes             map[int]struct{}
	RCode              string
	hasRCodes          bool
	Resume             bool
	resumeCfg          *ResumeCfg
	HostsFile          bool
	Stream             bool
	CAA                bool
	QueryAll           bool
	ExcludeType        []string
	OutputCDN          bool
	ASN                bool
	HealthCheck        bool
	DisableUpdateCheck bool
	PdcpAuth           string
}

// ShouldLoadResume resume file
func (options *Options) ShouldLoadResume() bool {
	return options.Resume && fileutil.FileExists(DefaultResumeFile)
}

// ShouldSaveResume file
func (options *Options) ShouldSaveResume() bool {
	return true
}

// ParseOptions parses the command line options for application
func ParseOptions(domain, dictfile string) *Options {
	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`dnsx is a fast and multi-purpose DNS toolkit allow to run multiple probes using retryabledns library.`)
	//修改dnsxflag部分，直接调用
	//TODO 可否传入[]string，dnsx内部是否已经实现多线程？
	options.Domains = domain
	options.WordList = dictfile
	//默认线程100
	options.Threads = 100
	// 关闭每秒请求数量限制
	options.RateLimit = -1

	options.A = true
	options.AAAA = false
	options.CNAME = false
	options.NS = false
	options.TXT = false
	options.SRV = false
	options.PTR = false
	options.MX = false
	options.SOA = false
	options.AXFR = false
	options.CAA = false

	options.Response = false
	options.ResponseOnly = false
	options.RCode = ""

	options.OutputCDN = false
	options.ASN = false

	options.DisableUpdateCheck = true

	options.OutputFile = ""
	options.JSON = false

	options.HealthCheck = false
	options.Silent = false
	options.Verbose = false

	options.Raw = false
	options.ShowStatistics = false
	options.Version = false

	// 重试次数
	options.Retries = 2
	options.HostsFile = false
	options.Trace = false
	options.TraceMaxRecursion = math.MaxInt16
	options.Resume = false
	options.Stream = false

	options.Resolvers = ""
	options.WildcardThreshold = 5
	options.WildcardDomain = ""

	if options.HealthCheck {
		gologger.Print().Msgf("%s\n", DoHealthCheck(options, flagSet))
		os.Exit(0)
	}

	options.configureQueryOptions()

	// Read the inputs and configure the logging
	options.configureOutput()

	err := options.configureRcodes()
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	err = options.configureResume()
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", version)
		os.Exit(0)
	}

	if !options.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("dnsx", version)()
		if err != nil {
			if options.Verbose {
				gologger.Error().Msgf("dnsx version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current dnsx version %v %v", version, updateutils.GetVersionDescription(version, latestVersion))
		}
	}

	options.validateOptions()

	return options
}

func (options *Options) validateOptions() {
	if options.Response && options.ResponseOnly {
		gologger.Fatal().Msgf("resp and resp-only can't be used at the same time")
	}

	if options.Retries == 0 {
		gologger.Fatal().Msgf("retries must be at least 1")
	}

	wordListPresent := options.WordList != ""
	domainsPresent := options.Domains != ""
	hostsPresent := options.Hosts != ""

	if hostsPresent && (wordListPresent || domainsPresent) {
		gologger.Fatal().Msgf("list(l) flag can not be used domain(d) or wordlist(w) flag")
	}

	if wordListPresent && !domainsPresent {
		gologger.Fatal().Msg("missing domain(d) flag required with wordlist(w) input")
	}
	if domainsPresent && !wordListPresent {
		gologger.Fatal().Msgf("missing wordlist(w) flag required with domain(d) input")
	}

	// stdin can be set only on one flag
	if argumentHasStdin(options.Domains) && argumentHasStdin(options.WordList) {
		if options.Stream {
			gologger.Fatal().Msgf("argument stdin not supported in stream mode")
		}
		gologger.Fatal().Msgf("stdin can be set for one flag")
	}

	if options.Stream {
		if wordListPresent {
			gologger.Fatal().Msgf("wordlist not supported in stream mode")
		}
		if domainsPresent {
			gologger.Fatal().Msgf("domains not supported in stream mode")
		}
		if options.Resume {
			gologger.Fatal().Msgf("resume not supported in stream mode")
		}
		if options.WildcardDomain != "" {
			gologger.Fatal().Msgf("wildcard not supported in stream mode")
		}
		if options.ShowStatistics {
			gologger.Fatal().Msgf("stats not supported in stream mode")
		}
	}
}

func argumentHasStdin(arg string) bool {
	return arg == stdinMarker
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}

func (options *Options) configureRcodes() error {
	options.rcodes = make(map[int]struct{})
	rcodes := strings.Split(options.RCode, ",")
	for _, rcode := range rcodes {
		var rc int
		switch strings.ToLower(rcode) {
		case "":
			continue
		case "noerror":
			rc = 0
		case "formerr":
			rc = 1
		case "servfail":
			rc = 2
		case "nxdomain":
			rc = 3
		case "notimp":
			rc = 4
		case "refused":
			rc = 5
		case "yxdomain":
			rc = 6
		case "yxrrset":
			rc = 7
		case "nxrrset":
			rc = 8
		case "notauth":
			rc = 9
		case "notzone":
			rc = 10
		case "badsig", "badvers":
			rc = 16
		case "badkey":
			rc = 17
		case "badtime":
			rc = 18
		case "badmode":
			rc = 19
		case "badname":
			rc = 20
		case "badalg":
			rc = 21
		case "badtrunc":
			rc = 22
		case "badcookie":
			rc = 23
		default:
			var err error
			rc, err = strconv.Atoi(rcode)
			if err != nil {
				return errors.New("invalid rcode value")
			}
		}

		options.rcodes[rc] = struct{}{}
	}

	options.hasRCodes = options.RCode != ""

	// Set rcode to 0 if none was specified
	if len(options.rcodes) == 0 {
		options.rcodes[0] = struct{}{}
	}

	return nil
}

func (options *Options) configureResume() error {
	options.resumeCfg = &ResumeCfg{}
	if options.Resume && fileutil.FileExists(DefaultResumeFile) {
		return goconfig.Load(&options.resumeCfg, DefaultResumeFile)

	}
	return nil
}

func (options *Options) configureQueryOptions() {
	queryMap := map[string]*bool{
		"a":     &options.A,
		"aaaa":  &options.AAAA,
		"cname": &options.CNAME,
		"ns":    &options.NS,
		"txt":   &options.TXT,
		"srv":   &options.SRV,
		"ptr":   &options.PTR,
		"mx":    &options.MX,
		"soa":   &options.SOA,
		"axfr":  &options.AXFR,
		"caa":   &options.CAA,
		"any":   &options.ANY,
	}

	if options.QueryAll {
		for _, val := range queryMap {
			*val = true
		}
		options.Response = true
		// the ANY query type is not supported by the retryabledns library,
		// thus it's hard to filter the results when it's used in combination with other query types
		options.ExcludeType = append(options.ExcludeType, "any")
	}

	for _, et := range options.ExcludeType {
		if val, ok := queryMap[et]; ok {
			*val = false
		}
	}
}
