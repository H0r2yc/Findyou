package fingerprint

import (
	"fmt"
	"regexp"
	"strings"
)

func FindInBody(body string) {
	if strings.Contains(body, "beian.miit.gov.cn") || strings.Contains(body, "ICP备") { // 定义正则表达式
		re := regexp.MustCompile(`.ICP备\d+号(-\d+)?`)
		// 在 HTML 文本中查找备案号
		matches := re.FindStringSubmatch(body)
		// 如果找到匹配项，则输出备案号
		if len(matches) > 1 {
			fmt.Println("备案号:", matches[0])
		} else {
			fmt.Println("未找到备案号")
		}
	}
	if strings.Contains(body, "技术支持") || strings.Contains(body, "技术服务") {
		re := regexp.MustCompile(`技术支持.*?公司`)
		// 在 HTML 文本中查找备案号
		matches := re.FindStringSubmatch(body)
		// 如果找到匹配项，则输出备案号
		if len(matches) > 1 {
			fmt.Println("技术支持:", matches[1])
		} else {
			re = regexp.MustCompile(`技术服务.*?公司`)
			// 在 HTML 文本中查找备案号
			matches = re.FindStringSubmatch(body)
			if len(matches) > 1 {
				fmt.Println("技术服务", matches[1])
			} else {
				fmt.Println("未找到备案号")
			}
		}

		//这方面后面遇到再继续补充
	}
	if strings.Contains(body, "联系方式") || strings.Contains(body, "微信号") || strings.Contains(body, "客服电话") {
		re := regexp.MustCompile(`联系方式.*?1\d{10}`)
		// 在 HTML 文本中查找备案号
		matches := re.FindStringSubmatch(body)
		// 如果找到匹配项，则输出备案号
		if len(matches) > 1 {
			fmt.Println("联系方式:", matches[1])
		} else {
			re = regexp.MustCompile(`微信号.*?1\d{10}`)
			// 在 HTML 文本中查找备案号
			matches = re.FindStringSubmatch(body)
			if len(matches) > 1 {
				fmt.Println("联系方式:", matches[1])
			} else {
				re = regexp.MustCompile(`客服电话.*?1\d{10}`)
				// 在 HTML 文本中查找备案号
				matches = re.FindStringSubmatch(body)
				if len(matches) > 1 {
					fmt.Println("联系方式:", matches[1])
				} else {
					fmt.Println("未找到备案号")
				}
			}
		}
	}
}
