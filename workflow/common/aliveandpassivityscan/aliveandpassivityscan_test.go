package aliveandpassivityscan

import (
	"Findyou.WorkFlow/common/loadyaml"
	"Findyou.WorkFlow/common/onlineengine"
	"Findyou.WorkFlow/common/workflowstruct"
	"strings"
	"testing"
)

// 测试函数
func TestAliveAndPassivityScan(t *testing.T) {
	loadyaml.Loadyaml()
	targetlist := []string{"http://39.104.77.27/seeyon/index.jsp"}
	appconfig := workflowstruct.Appconfig{
		Fingerprint: workflowstruct.Fingerprint{
			IsScreenshot:     false,
			IsFingerprintHub: false,
			IsFingerprintx:   false,
			CustomDir:        nil,
		},
	}
	AliveAndPassivityScan(targetlist, &appconfig)
}

// 定义一个测试函数，用于测试某个方法
func TestAliveAndPassivityScan2(t *testing.T) {
	loadyaml.Loadyaml()
	targetlist := []string{"218.91.99.56"}
	var fofasearchwordlist []string
	// 每 10 条生成一个新的字符串
	for i := 0; i < len(targetlist); i += 50 {
		end := i + 50
		if end > len(targetlist) {
			end = len(targetlist)
		}

		// 生成字符串 xxx=target1||xxx=target2||...
		sublist := targetlist[i:end]
		joined := "ip=\"" + strings.Join(sublist, "\" || ip=\"") + "\""
		fofasearchwordlist = append(fofasearchwordlist, joined)
	}
	var ipurllist []string
	for _, fofasearch := range fofasearchwordlist {
		result := onlineengine.SearchFOFACore(fofasearch, "yiheng6221@163.com:73a981a7b5b4959fa50588051444021c", 9000, 100)
		ipurllist = append(ipurllist, result.Targets...)
	}
	appconfig := workflowstruct.Appconfig{
		Httpxconfig: workflowstruct.Httpx{
			WebTimeout: 5,
			WebThreads: 200,
			HTTPProxy:  "",
		},
	}
	AliveAndPassivityScan(ipurllist, &appconfig)
}
