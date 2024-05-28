package fingerprint

import (
	"github.com/projectdiscovery/gologger"
	"regexp"
	"strings"
)

type BodyData struct {
	ICP         string
	Supplychain string
	PhoneNum    string
}

func FindInBody(body string) BodyData {
	Bodydata := BodyData{}
	if strings.Contains(body, "beian.miit.gov.cn") || strings.Contains(body, "ICP备") { // 定义正则表达式
		re := regexp.MustCompile(`.ICP备\d+号(-\d+)?`)
		// 在 HTML 文本中查找备案号
		matches := re.FindString(body)
		// 如果找到匹配项，则输出备案号
		if matches != "" {
			Bodydata.ICP = matches
			gologger.Info().Msgf("备案号:%s", matches)
		}
	}
	if strings.Contains(body, "技术支持") || strings.Contains(body, "技术服务") {
		re := regexp.MustCompile(`技术支持.*?公司`)
		// 在 HTML 文本中查找备案号
		matches := re.FindString(body)
		// 如果找到匹配项，则输出备案号
		if matches != "" {
			Bodydata.Supplychain = matches
			gologger.Info().Msgf("技术支持:%s", matches)
		} else {
			re = regexp.MustCompile(`由.*?提供技术支持`)
			// 在 HTML 文本中查找备案号
			matches = re.FindString(body)
			// 如果找到匹配项，则输出备案号
			if matches != "" {
				Bodydata.Supplychain = matches
				gologger.Info().Msgf("技术支持:%s", matches)
			} else {
				re = regexp.MustCompile(`技术服务.*?公司`)
				// 在 HTML 文本中查找备案号
				matches = re.FindString(body)
				if matches != "" {
					Bodydata.Supplychain = matches
					gologger.Info().Msgf("技术服务:%s", matches)
				}
			}
		}
		//这方面后面遇到再继续补充
	}
	if strings.Contains(body, "联系方式") || strings.Contains(body, "微信号") || strings.Contains(body, "客服电话") {
		re := regexp.MustCompile(`0?(13[0-9]|15[012356789]|17[013678]|18[0-9]|14[57])[0-9]{8}`)
		// 在 HTML 文本中查找备案号
		matches := re.FindString(body)
		// 如果找到匹配项，则输出备案号
		if matches != "" {
			Bodydata.PhoneNum = matches
			gologger.Info().Msgf("联系方式:%s", matches)
		} else {
			re = regexp.MustCompile(`0?(13[0-9]|15[012356789]|17[013678]|18[0-9]|14[57])[0-9]{8}`)
			// 在 HTML 文本中查找备案号
			matches = re.FindString(body)
			if matches != "" {
				Bodydata.PhoneNum = matches
				gologger.Info().Msgf("微信号:%s", matches)
			} else {
				re = regexp.MustCompile(`0?(13[0-9]|15[012356789]|17[013678]|18[0-9]|14[57])[0-9]{8}`)
				// 在 HTML 文本中查找备案号
				matches = re.FindString(body)
				if matches != "" {
					Bodydata.PhoneNum = matches
					gologger.Info().Msgf("客服电话:%s", matches)
				}
			}
		}
	}
	return Bodydata
}
