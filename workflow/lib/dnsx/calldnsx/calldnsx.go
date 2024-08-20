package calldnsx

import (
	"github.com/projectdiscovery/dnsx/internal/runner"
	"github.com/projectdiscovery/gologger"
)

func CallDNSX(domain, subdomainfile string) []string {
	dnsxoptions := runner.ParseOptions(domain, subdomainfile)
	dnsxRunner, err := runner.New(dnsxoptions)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	gologger.Info().Msgf("开始爆破子域名%v", domain)
	dnsxRunner.Run()
	dnsxRunner.Close()
	return dnsxRunner.SubdomainResults
}
