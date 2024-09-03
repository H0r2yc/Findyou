package utils

import "strings"

func SplitSlice(strs []string, num int) [][]string {
	// 确保 num 大于 0
	if num <= 0 {
		return nil
	}

	// 计算每份的大小
	chunkSize := (len(strs) + num - 1) / num

	// 创建一个包含 num 个切片的切片
	result := make([][]string, 0, num)

	// 分割 strs 切片
	for i := 0; i < len(strs); i += chunkSize {
		end := i + chunkSize
		if end > len(strs) {
			end = len(strs)
		}
		result = append(result, strs[i:end])
	}
	return result
}

func TaskDataToKeywordData(TaskData []string) []string {
	var keywords []string
	for _, task := range TaskData {
		keyord := strings.SplitN(task, "Findyou", 2)
		keywords = append(keywords, keyord[0])
	}
	return keywords
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
