package dirbrute

import (
	"Findyou.WorkFlow/common/loadyaml"
	"Findyou.WorkFlow/common/workflowstruct"
	"testing"
)

// 测试函数
func TestDirBrute(t *testing.T) {
	loadyaml.Loadyaml()
	targetlist := []string{"guanyuanbi.xiaohongshu.com"}
	appconfig := workflowstruct.Appconfig{
		Fingerprint: workflowstruct.Fingerprint{
			IsScreenshot:     false,
			EnableActiveScan: true,
			IsFingerprintHub: false,
			IsFingerprintx:   false,
			CustomDir:        nil,
		},
	}
	DirBrute(targetlist, &appconfig)
}
