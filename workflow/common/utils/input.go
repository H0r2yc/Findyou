package utils

import (
	"net"
	"strings"
)

// 查找一个str是否存在于切片中
func StringInSlice(target string, slice []string) bool {
	for _, item := range slice {
		if strings.Contains(item, target) {
			return true
		}
	}
	return false
}

// IsIPv4 IsIP checks if a string is either IP version 4 Alias for `net.ParseIP`
func IsIPv4(str string) bool {
	for i := 0; i < len(str); i++ {
		if str[i] == '.' {
			return net.ParseIP(str) != nil
		}
	}
	return false
}

// IsIPv6 IsIP checks if a string is either IP version 4 Alias for `net.ParseIP`
func IsIPv6(str string) bool {
	for i := 0; i < len(str); i++ {
		if str[i] == ':' {
			return net.ParseIP(str) != nil
		}
	}
	return false
}

func FromKeywordGetDomain(keyword string) string {
	if strings.Contains(keyword, "||") {
		firstkeyword := strings.Split(keyword, "||")[0]
		firstkeyword = strings.ReplaceAll(firstkeyword, "(", "")
		firstkeyword = strings.ReplaceAll(firstkeyword, ")", "")
		if strings.Contains(firstkeyword, "&&") {
			keyword = strings.Split(strings.Split(firstkeyword, "&&")[0], "=")[1]
		} else {
			keyword = strings.Split(firstkeyword, "=")[1]
		}
	} else {
		if strings.Contains(keyword, "&&") {
			keyword = strings.Split(strings.Split(keyword, "&&")[0], "=")[1]
		} else {
			keyword = strings.Split(keyword, "=")[1]
		}
	}
	return keyword
}

func RemoveDuplicateElement(input []string) []string {
	temp := map[string]struct{}{}
	var result []string
	for _, item := range input {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func GetItemInArray(a []string, s string) int {
	for index, v := range a {
		if v == s {
			return index
		}
	}
	return -1
}
