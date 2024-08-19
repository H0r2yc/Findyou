package httpxscan

import (
	"Findyou.WorkFlow/common/loadyaml"
	"Findyou.WorkFlow/common/workflowstruct"
	"testing"
)

// 定义一个测试函数，用于测试某个方法
func TestHttpxscan(t *testing.T) {
	loadyaml.Loadyaml()
	targetlist := []string{"www.wactl.com/athena/"}
	appconfig := workflowstruct.Appconfig{
		Httpxconfig: workflowstruct.Httpx{
			WebTimeout: 5,
			WebThreads: 100,
			HTTPProxy:  "",
		},
	}
	Httpxscan(targetlist, &appconfig)
}
