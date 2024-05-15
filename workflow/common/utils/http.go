package utils

import (
	"Findyou.WorkFlow/common/workflowstruct"
	"container/list"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func SingleCheck(finger workflowstruct.FingerPEntity, Protocol string, headerString string, body string,
	Server string, Title string, Cert string, Port int, Path string, Hash string, IconHash string, StatusCode int,
	ContentType string, Banner string) bool {
	rules := finger.Rule
	expr := finger.AllString

	for _, singleRule := range rules {
		singleRuleResult := false
		if singleRule.Key == "header" {
			if DataCheckString(singleRule.Op, headerString, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "body" {
			if DataCheckString(singleRule.Op, body, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "server" {
			if DataCheckString(singleRule.Op, Server, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "title" {
			if DataCheckString(singleRule.Op, Title, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "cert" {
			if DataCheckString(singleRule.Op, Cert, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "port" {
			value, err := strconv.Atoi(singleRule.Value)
			if err == nil && DataCheckInt(singleRule.Op, Port, value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "protocol" {
			if singleRule.Op == 0 {
				if Protocol == singleRule.Value {
					singleRuleResult = true
				}
			} else if singleRule.Op == 1 {
				if Protocol != singleRule.Value {
					singleRuleResult = true
				}
			}
		} else if singleRule.Key == "path" {
			if DataCheckString(singleRule.Op, Path, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "body_hash" {

			if DataCheckString(singleRule.Op, Hash, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "icon_hash" {
			value, err := strconv.Atoi(singleRule.Value)
			hashIcon, errHash := strconv.Atoi(IconHash)
			if err == nil && errHash == nil && DataCheckInt(singleRule.Op, hashIcon, value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "status" {
			value, err := strconv.Atoi(singleRule.Value)
			if err == nil && DataCheckInt(singleRule.Op, StatusCode, value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "content_type" {
			if DataCheckString(singleRule.Op, ContentType, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "banner" {
			if DataCheckString(singleRule.Op, Banner, singleRule.Value) {
				singleRuleResult = true
			}
		} else if singleRule.Key == "type" {
			if singleRule.Value == "service" {
				singleRuleResult = true
			}
		}
		if singleRuleResult {
			expr = expr[:singleRule.Start] + "T" + expr[singleRule.End:]
		} else {
			expr = expr[:singleRule.Start] + "F" + expr[singleRule.End:]
		}
	}

	return BoolEval(expr)
}

// body="123"  op=0  dataSource为http.body dataRule=123
func DataCheckString(op int16, dataSource string, dataRule string) bool {
	dataSource = strings.ToLower(dataSource)

	dataRule = strings.ToLower(dataRule)
	dataRule = strings.ReplaceAll(dataRule, "\\\"", "\"")
	if op == 0 {
		if strings.Contains(dataSource, dataRule) {
			return true
		}
	} else if op == 1 {
		if !strings.Contains(dataSource, dataRule) {
			return true
		}
	} else if op == 2 {
		if dataSource == dataRule {
			return true
		}
	} else if op == 5 {
		rs, err := regexMatch(dataRule, dataSource)
		if err == nil && rs {
			return true
		}
	}
	return false
}

func regexMatch(pattern string, s string) (bool, error) {
	matched, err := regexp.MatchString(pattern, s)
	if err != nil {
		return false, err
	}
	return matched, nil
}

func DataCheckInt(op int16, dataSource int, dataRule int) bool {
	if op == 0 { // 数字相等
		if dataSource == dataRule {
			return true
		}
	} else if op == 1 { // 数字不相等
		if dataSource != dataRule {
			return true
		}
	} else if op == 3 { // 大于等于
		if dataSource >= dataRule {
			return true
		}
	} else if op == 4 {
		if dataSource <= dataRule {
			return true
		}
	}
	return false
}

// 计算纯bool表达式，支持 ! && & || | ( )
func BoolEval(expression string) bool {
	// 左右括号相等
	if strings.Count(expression, "(") != strings.Count(expression, ")") {
		gologger.Fatal().Msg(fmt.Sprintf("[-] 纯布尔表达式 [%s] 左右括号不匹配", expression))
	}
	// 去除空格
	for strings.Contains(expression, " ") {
		expression = strings.ReplaceAll(expression, " ", "")
	}
	// 去除空表达式
	for strings.Contains(expression, "()") {
		expression = strings.ReplaceAll(expression, "()", "")
	}
	for strings.Contains(expression, "&&") {
		expression = strings.ReplaceAll(expression, "&&", "&")
	}
	for strings.Contains(expression, "||") {
		expression = strings.ReplaceAll(expression, "||", "|")
	}
	if !strings.Contains(expression, "T") && !strings.Contains(expression, "F") {
		return false
		// panic("纯布尔表达式错误，没有包含T/F")
	}

	expr := list.New()
	operator_stack := list.New()
	for _, ch := range expression {
		// ch 为 T或者F
		if ch == 84 || ch == 70 {
			expr.PushBack(int(ch))
		} else if advance(int(ch)) > 0 {
			if operator_stack.Len() == 0 {
				operator_stack.PushBack(int(ch))
				continue
			}
			// 两个!抵消
			if ch == 33 && operator_stack.Back().Value.(int) == 33 {
				operator_stack.Remove(operator_stack.Back())
				continue
			}
			for operator_stack.Len() != 0 && operator_stack.Back().Value.(int) != 40 && advance(operator_stack.Back().Value.(int)) >= advance(int(ch)) {
				e := operator_stack.Back()
				expr.PushBack(e.Value.(int))
				operator_stack.Remove(e)
			}
			operator_stack.PushBack(int(ch))

		} else if ch == 40 {
			operator_stack.PushBack(int(ch))
		} else if ch == 40 {
			for operator_stack.Back().Value.(int) != 40 {
				e := operator_stack.Back()
				expr.PushBack(e.Value.(int))
				operator_stack.Remove(e)
			}
			operator_stack.Remove(operator_stack.Back())
		}
	}
	for operator_stack.Len() != 0 {
		e := operator_stack.Back()
		expr.PushBack(e.Value.(int))
		operator_stack.Remove(e)
	}

	tf_stack := list.New()
	for expr.Len() != 0 {
		e := expr.Front()
		ch := e.Value.(int)
		expr.Remove(e)
		if ch == 84 || ch == 70 {
			tf_stack.PushBack(int(ch))
		}
		if ch == 38 { // &
			em := tf_stack.Back()
			a := em.Value.(int)
			tf_stack.Remove(em)
			em = tf_stack.Back()
			b := em.Value.(int)
			tf_stack.Remove(em)
			if a == 84 && b == 84 {
				tf_stack.PushBack(84)
			} else {
				tf_stack.PushBack(70)
			}
		}
		if ch == 124 { // |
			em := tf_stack.Back()
			a := em.Value.(int)
			tf_stack.Remove(em)
			em = tf_stack.Back()
			b := em.Value.(int)
			tf_stack.Remove(em)
			if a == 70 && b == 70 {
				tf_stack.PushBack(70)
			} else {
				tf_stack.PushBack(84)
			}
		}
		if ch == 33 { // !
			em := tf_stack.Back()
			a := em.Value.(int)
			tf_stack.Remove(em)
			if a == 70 {
				tf_stack.PushBack(84)
			} else if a == 84 {
				tf_stack.PushBack(70)
			}
		}
	}
	if tf_stack.Front().Value.(int) == 84 {
		return true
	} else {
		return false
	}

}

// 判断优先级 非运算符返回0
func advance(ch int) int {
	// !
	if ch == 33 {
		return 3
	}
	// &
	if ch == 38 {
		return 2
	}
	// |
	if ch == 124 {
		return 1
	}
	return 0
}

func GetTLSString(resp runner.Result) string {
	result := ""
	if resp.TLSData == nil {
		return result
	}

	result += "SubjectCN: " + resp.TLSData.SubjectCN + "\n"
	result += "SubjectDN: " + resp.TLSData.SubjectDN + "\n"

	result += "IssuerCN: " + resp.TLSData.IssuerCN + "\n"
	result += "IssuerDN: " + resp.TLSData.IssuerDN + "\n"

	result += "IssuerOrg: \n"
	for _, v := range resp.TLSData.IssuerOrg {
		result += "    - " + v + "\n"
	}

	return result
}

func URLParse(URLRaw string) *url.URL {
	URL, _ := url.Parse(URLRaw)
	return URL
}
