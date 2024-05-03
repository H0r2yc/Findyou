package nuclei

import (
	"Findyou/common/config"
	"Findyou/common/db"
	"github.com/projectdiscovery/gologger"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/remeh/sizedwaitgroup"
)

func NucleiScan(appconfig *config.Appconfig) {
	targets, err := db.GetAllTargets(1)
	if err != nil {
		gologger.Error().Msg(err.Error())
	}
	if len(targets) == 0 {
		return
	}
	gologger.Info().Msg("获取Web响应中")

	// 分割目标列表
	chunkSize := len(targets) / appconfig.Nucleiconfig.Threads // 将目标列表分成 10 份
	var targetChunks [][]string
	for i := 0; i < len(targets); i += chunkSize {
		end := i + chunkSize
		if end > len(targets) {
			end = len(targets)
		}
		targetChunks = append(targetChunks, getTargetList(targets[i:end]))
	}

	// create nuclei engine with options
	ne, err := nuclei.NewThreadSafeNucleiEngine()
	if err != nil {
		panic(err)
	}
	// setup sizedWaitgroup to handle concurrency
	// here we are using sizedWaitgroup to limit concurrency to 1
	// but can be anything in general
	sg := sizedwaitgroup.New(appconfig.Nucleiconfig.Threads)

	// 为每个目标列表启动一个线程
	for _, chunk := range targetChunks {
		sg.Add()
		go func(targets []string) {
			defer sg.Done()
			// 在这里执行扫描任务
			performScan(ne, targets)
		}(chunk)
	}

	// 等待所有扫描任务完成
	sg.Wait()
	defer ne.Close()
}

// 将目标列表转换为字符串列表
func getTargetList(targets []db.Targets) []string {
	var targetList []string
	for _, target := range targets {
		targetList = append(targetList, target.Target)
	}
	return targetList
}

// 执行扫描任务
func performScan(ne *nuclei.ThreadSafeNucleiEngine, targets []string) {
	err := ne.ExecuteNucleiWithOpts(targets, nuclei.WithTemplateFilters(nuclei.TemplateFilters{IDs: []string{"nameserver-fingerprint"}}))
	if err != nil {
		panic(err)
	}
}
