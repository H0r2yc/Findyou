package aliveandpassivityscan

import (
	"Findyou.WorkFlow/common/loadyaml"
	"Findyou.WorkFlow/common/workflowstruct"
	"bufio"
	"fmt"
	"os"
	"testing"
)

// 测试函数
func TestAliveAndPassivityScan(t *testing.T) {
	loadyaml.Loadyaml()
	targetlist := []string{"https://xxx"}
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

// 从本地文件直接探活+指纹识别
func TestAliveAndPassivityScanFromFile(t *testing.T) {
	loadyaml.Loadyaml()
	filename := "C:\\Users\\Lenovo\\Desktop\\url.txt"
	// 打开文件
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	// 创建一个切片来存储每一行
	var targetlist []string

	// 使用bufio.Scanner按行读取文件
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		targetlist = append(targetlist, scanner.Text())
	}
	// 检查是否有读取错误
	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
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
