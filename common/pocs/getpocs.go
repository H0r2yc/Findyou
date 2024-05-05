package pocs

import (
	"Findyou/common/config"
	"Findyou/common/utils"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"strings"
)

func GetPocs(workflowDB map[string]config.WorkFlowEntity) (map[string][]string, int) {
	gologger.AuditTimeLogger("根据指纹选择Poc")
	result := make(map[string][]string)
	count := 0

	var generalKeys []string
	if !config.GlobalConfig.DisableGeneralPoc {
		for k, workflowEntity := range workflowDB {
			if strings.Contains(k, "General-Poc-") {
				if len(workflowEntity.PocsName) == 0 {
					continue
				}
				generalKeys = append(generalKeys, k)
			}
		}
	}

	for target, fingerprints := range config.GlobalResultMap {
		gologger.AuditLogger(target + ":")
		for _, finger := range fingerprints {
			workflowEntity, ok := workflowDB[finger]
			if !ok || len(workflowEntity.PocsName) == 0 {
				continue
			}

			if !strings.Contains(target, "http") {
				if !workflowEntity.RootType { // 与Root无关
					continue
				}
				addPocs(target, &result, workflowEntity)
				count++
			} else {
				Url := utils.URLParse(target)

				// Web
				if workflowEntity.RootType {
					rootURL := fmt.Sprintf("%s://%s", Url.Scheme, Url.Host)
					addPocs(rootURL, &result, workflowEntity)
					count++

				}

				if (Url.Path != "/" && Url.Path != "") && workflowEntity.BaseType {
					addPocs(target, &result, workflowEntity)
					count++
				}

				if (Url.Path != "/" && Url.Path != "") && workflowEntity.DirType {
					splitPath := strings.Split(Url.Path, "/")
					for i := 1; i < len(splitPath); i++ {
						newPath := strings.Join(splitPath[:i], "/")
						t := fmt.Sprintf("%s://%s%s", Url.Scheme, Url.Host, newPath)
						addPocs(t, &result, workflowEntity)
						count++
					}

				}
			}

		}

		for _, key := range generalKeys {
			workflowEntity, ok := workflowDB[key]
			if !ok || len(workflowEntity.PocsName) == 0 {
				continue
			}

			if !strings.Contains(target, "http") {
				if !workflowEntity.RootType { // 与Root无关
					continue
				}
				addPocs(target, &result, workflowEntity)
				count++
			} else {
				Url := utils.URLParse(target)

				// Web
				if workflowEntity.RootType {
					rootURL := fmt.Sprintf("%s://%s", Url.Scheme, Url.Host)
					addPocs(rootURL, &result, workflowEntity)
					count++
				}

				if (Url.Path != "/" && Url.Path != "") && workflowEntity.BaseType {
					addPocs(target, &result, workflowEntity)
					count++
				}

				if (Url.Path != "/" && Url.Path != "") && workflowEntity.DirType {
					splitPath := strings.Split(Url.Path, "/")
					for i := 1; i < len(splitPath); i++ {
						newPath := strings.Join(splitPath[:i], "/")
						t := fmt.Sprintf("%s://%s%s", Url.Scheme, Url.Host, newPath)
						addPocs(t, &result, workflowEntity)
						count++
					}

				}
			}
		}

	}
	return result, count
}

func AddYamlSuffix(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, ".yaml") {
		return s
	} else {
		return s + ".yaml"
	}
}

func addPocs(target string, result *map[string][]string, workflowEntity config.WorkFlowEntity) {
	// 判断有没有加入过
	_, ok := (*result)[target]
	if !ok { // 没有添加过这个目标
		(*result)[target] = []string{}
		for _, pocName := range workflowEntity.PocsName {
			(*result)[target] = append((*result)[target], AddYamlSuffix(pocName))
			gologger.AuditLogger("    - " + pocName)
		}
	} else { // 添加过就逐个比较
		existPocNames, _ := (*result)[target]
		for _, pocName := range workflowEntity.PocsName {
			// 没有就添加
			if utils.GetItemInArray(existPocNames, pocName) == -1 {
				(*result)[target] = append((*result)[target], AddYamlSuffix(pocName))
				gologger.AuditLogger("    - " + pocName)
			}
		}
	}
}
