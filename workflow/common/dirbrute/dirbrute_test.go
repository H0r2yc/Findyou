package dirbrute

import (
	"Findyou.WorkFlow/common/loadyaml"
	"Findyou.WorkFlow/common/workflowstruct"
	"testing"
)

// 测试函数
func TestDirBrute(t *testing.T) {
	loadyaml.Loadyaml()
	targetlist := []string{"http://39.104.77.27"}
	appconfig := workflowstruct.Appconfig{
		Fingerprint: workflowstruct.Fingerprint{
			IsScreenshot:     false,
			IsFingerprintHub: false,
			IsFingerprintx:   false,
			CustomDir:        nil,
		},
	}
	DirBrute(targetlist, &appconfig)
}
