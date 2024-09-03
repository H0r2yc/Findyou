package subdomainbrute

import (
	"bytes"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"io"
	"strings"
)

func subfinder(domain string) ([]string, error) {
	runnerInstance, err := runner.NewRunner(&runner.Options{
		Threads:            10,                       // Thread controls the number of threads to use for active enumerations
		Timeout:            15,                       // Timeout is the seconds to wait for sources to respond
		MaxEnumerationTime: 5,                        // MaxEnumerationTime is the maximum amount of time in mins to wait for enumeration
		Resolvers:          resolve.DefaultResolvers, // Use the default list of resolvers by marshaling it to the config
		//ResultCallback: func(s *resolve.HostEntry) { // Callback function to execute for available host
		// gologger.Silent().Msgf("[%s] %s", s.Source, s.Host)
		//	gologger.Info().Msg(s.Domain)
		//},
		RemoveWildcard:     true,
		DisableUpdateCheck: true,
		ProviderConfig:     "config/subfinder-config.yaml",
	})

	buf := bytes.Buffer{}
	err = runnerInstance.EnumerateSingleDomain(domain, []io.Writer{&buf})
	if err != nil {
		gologger.Error().Msg(err.Error())
	}

	data, err := io.ReadAll(&buf)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	subdomains := strings.Split(string(data), "\n")
	return subdomains, err
}
