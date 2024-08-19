package subdomainbrute

import (
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
)

//计划结合subfinder，ksubdomain，然后httpx做存活探测并加入到domain以及targets

func DnsX(domain string) error {
	dnsxoptions := dnsx.Options{
		BaseResolvers:     nil,
		MaxRetries:        0,
		QuestionTypes:     nil,
		Trace:             false,
		TraceMaxRecursion: 0,
		Hostsfile:         false,
		OutputCDN:         false,
		QueryAll:          true,
	}
	// Create DNS Resolver with default options
	dnsClient, err := dnsx.New(dnsxoptions)
	if err != nil {
		gologger.Info().Msgf("err: %v\n", err)
		return err
	}
	// Query
	rawResp, err := dnsClient.QueryOne(domain)
	if err != nil {
		gologger.Info().Msgf("err: %v\n", err)
		return err
	}
	jsonStr, err := rawResp.JSON()
	if err != nil {
		gologger.Info().Msgf("err: %v\n", err)
		return err
	}
	gologger.Info().Msg(jsonStr)
	return nil
}
