package fingerprint

import (
	"Findyou.WorkFlow/common/workflowstruct"
	"github.com/projectdiscovery/httpx/runner"
	"strings"
)

func Fingerprint(resp runner.Result) (string, int, bool) {
	var (
		fingername string
		priority   int
		matched    bool
	)
	for _, finger := range workflowstruct.FingerPrints {
		result := matchfinger(resp, finger)
		if !result {
			continue
		} else {
			fingername = finger.Name
			priority = finger.Priority
			matched = true
			break
		}
	}
	return fingername, priority, matched
}

func matchfinger(resp runner.Result, finger workflowstruct.Fingerprints) bool {
	//先判断statuscode节省资源
	if finger.StatusCode != 0 {
		if resp.StatusCode != finger.StatusCode {
			return false
		}
	}
	if len(finger.FaviconHash) != 0 {
		//需要匹配任意一个即可，所以新增一个状态参数
		matched := false
		for _, hash := range finger.FaviconHash {
			if resp.IConHash_MD5 == hash {
				matched = true
			}
		}
		if !matched {
			return false
		}
	}
	if len(finger.Headers) != 0 {
		for key, value := range finger.Headers {
			if resp.ResponseHeaders[key] != value {
				return false
			}
		}
	}
	if len(finger.Keyword) != 0 {
		for _, keyword := range finger.Keyword {
			if !strings.Contains(resp.ResponseBody, keyword) {
				return false
			}
		}
	}
	return true
}
