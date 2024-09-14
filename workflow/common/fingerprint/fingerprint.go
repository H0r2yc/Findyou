package fingerprint

import (
	"Findyou.WorkFlow/common/httpxscan"
	"Findyou.WorkFlow/common/utils"
	"Findyou.WorkFlow/common/workflowstruct"
	"github.com/projectdiscovery/gologger"
	"net/url"
	"strings"
)

func Fingerprint(urlentity workflowstruct.Urlentity) (string, int, bool) {
	var (
		fingername []string
		priority   int
		matched    bool
	)
	for _, finger := range workflowstruct.FingerPrints {
		result := matchfinger(urlentity, finger)
		if result {
			fingername = append(fingername, finger.Name)
			priority = finger.Priority
			matched = true
		}
		if finger.Path != "/" || len(finger.RequestHeaders) > 0 || finger.RequestData != "" || strings.ToLower(finger.RequestMethod) != "get" {
			var urls []string
			if finger.Path != "/" {
				// 解析URL
				parsedURL, err := url.Parse(urlentity.Url)
				if err != nil {
					gologger.Error().Msg(err.Error())
				}
				parsedURL.Path = ""
				urls = append(urls, parsedURL.String()+finger.Path)
			} else {
				urls = append(urls, urlentity.Url)
			}
			ActiveUrlentity := httpxscan.HttpxActiveScan(finger.RequestMethod, finger.RequestData, urls, finger.RequestHeaders)
			result2 := matchfinger(ActiveUrlentity, finger)
			if result2 {
				fingername = append(fingername, finger.Name)
				priority = finger.Priority
				matched = true
			}
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
			matched := false
			for _, headervalue := range urlentity.Header[key] {
				if strings.Contains(headervalue, value) {
					matched = true
				}
			}
			if !matched {
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
