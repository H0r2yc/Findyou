package activefingerprint

import (
	"Findyou.WorkFlow/common/loadyaml"
	"Findyou.WorkFlow/common/utils"
	"testing"
)

// 测试函数
func TestActiveFingerprint(t *testing.T) {
	appconfig := utils.GetAppConf()
	loadyaml.Loadyaml()
	targetlist := []string{"https://njlx.jh96095.com/admin"}
	ActiveFingerprint(targetlist, appconfig)
}
