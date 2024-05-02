package onlineengine

import "Findyou/common/config"

func AddIPDomainMap(result config.Targets, ip, domain string) {
	//多线程可能涉及需要手动设置Lock和Unlock，待观察
	if result.DomainIPMap == nil {
		result.DomainIPMap = make(map[string][]string)
	}
	result.DomainIPMapLock.Lock()
	defer result.DomainIPMapLock.Unlock()
	_, ok := result.DomainIPMap[ip]
	if ok {
		// 存在于这个Map中
		dms, _ := result.DomainIPMap[ip]
		flag := false
		for _, dm := range dms {
			if dm == domain {
				flag = true
				break
			}
		}
		if !flag { // 没有这个域名
			result.DomainIPMap[ip] = append(result.DomainIPMap[ip],
				domain)
		}
	} else {
		result.DomainIPMap[ip] = []string{domain}
	}
}
