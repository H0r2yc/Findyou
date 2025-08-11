package cdn

import (
	"github.com/projectdiscovery/gologger"
	"testing"
)

// 识别目标是否是CDN资产
func TestCheckCDNs(t *testing.T) {
	Domains := []string{""}
	gologger.Info().Msgf("正在查询 [%v] 个域名是否为CDN资产", len(Domains))
	cdnDomains, normalDomains, domainips := CheckCDNs(Domains, 500)
	gologger.Info().Msgf("CDN资产为 [%v] 个", len(cdnDomains))
	for _, d := range normalDomains {
		gologger.Info().Msgf("域名%s ", d)
		//如果解析失败了，那么就以0.0.0.0替代
		if domainips[d] != nil {
			gologger.Info().Msgf("对应的解析ip： %s ", domainips[d])
		}
	}
}
