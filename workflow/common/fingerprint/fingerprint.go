package fingerprint

import (
	"Findyou.WorkFlow/common/utils"
	"Findyou.WorkFlow/common/workflowstruct"
	"strings"
)

func Fingerprint(urlentity workflowstruct.Urlentity) (string, int, bool) {
	var (
		fingername []string
		priority   int
		matched    bool
	)
	for _, finger := range workflowstruct.FingerPrints {
		//if finger.Name == "Sentry" {
		//	gologger.Info().Msg("ssss")
		//}
		result := matchfinger(urlentity, finger)
		if !result {
			continue
		} else {
			fingername = append(fingername, finger.Name)
			priority = finger.Priority
			matched = true
		}
	}
	fingername = utils.RemoveDuplicateElement(fingername)
	return strings.Join(fingername, ","), priority, matched
}

func matchfinger(urlentity workflowstruct.Urlentity, finger workflowstruct.Fingerprints) bool {
	//先判断statuscode节省资源
	if finger.StatusCode != 0 {
		if urlentity.StatusCode != finger.StatusCode {
			return false
		}
	}
	if len(finger.FaviconHash) != 0 {
		//需要匹配任意一个即可，所以新增一个状态参数
		matched := false
		for _, hash := range finger.FaviconHash {
			if urlentity.Iconhash_md5 == hash || urlentity.Iconhash_mmh3 == hash {
				matched = true
			}
		}
		if !matched {
			return false
		}
	}
	if len(finger.Headers) != 0 {
		for key, value := range finger.Headers {
			if urlentity.Header[key] != value {
				return false
			}
		}
	}
	if len(finger.Keyword) != 0 {
		for _, keyword := range finger.Keyword {
			if !strings.Contains(urlentity.Body, keyword) {
				return false
			}
		}
	}
	return true
}
