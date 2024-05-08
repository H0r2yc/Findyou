package onlineengine

import (
	"Findyou/common/config"
	"fmt"
)

func DBMakeKeyword(globalkeywords []string, data, datatype string) []string {
	//判断如果ip属于定义的归属地，那么就直接/24，如果不是那么就下面
	var searchlist []string
	if datatype == "IP" {
		for _, globalkeyword := range globalkeywords {
			//Todo 如果是归属地相同或者重点ip表中，那么就直接/24
			if globalkeyword != "" {
				searchlist = append(searchlist, fmt.Sprintf("ip=\"%s/24\" && title=\"%s\" && country=\"CN\" && region!=\"HK\" && region!=\"TW\"", data, globalkeyword))
			} else {
				//TODO 根据cert或者iconhash等等做匹配
				searchlist = append(searchlist, fmt.Sprintf("ip=\"%s/24\" && title=\"系统\" && country=\"CN\" && region!=\"HK\" && region!=\"TW\"", data))
			}
		}
		return searchlist
	} else if datatype == "Domains" {
		searchlist = append(searchlist, fmt.Sprintf("domain=\"%s\" && country=\"CN\" && region!=\"HK\" && region!=\"TW\"", data))
		return searchlist
	}
	return nil
}

func FofaMakeKeyword(targetlist *config.Targetconfig) []string {
	var searchlist []string
	for _, name := range targetlist.Target.Name {
		if name != "" {
			//searchlist = append(searchlist, fmt.Sprintf("icp.name=\"%s\"", name))
			searchlist = append(searchlist, fmt.Sprintf("cert=\"%s\"", name))
			searchlist = append(searchlist, fmt.Sprintf("title=\"%s\" && title=\"系统\"", name))
		}
	}
	for _, ip := range targetlist.Target.IP {
		if ip != "" {
			searchlist = append(searchlist, fmt.Sprintf("ip=\"%s\"", ip))
		}
	}
	for _, domain := range targetlist.Target.Domain {
		if domain != "" {
			searchlist = append(searchlist, fmt.Sprintf("domain=\"%s\"", domain))
			searchlist = append(searchlist, fmt.Sprintf("host=\"%s\"", domain))
			searchlist = append(searchlist, fmt.Sprintf("cert=\"%s\"", domain))
		}
	}
	for _, cert := range targetlist.Target.Cert {
		if cert != "" {
			searchlist = append(searchlist, fmt.Sprintf("cert=\"%s\"", cert))
		}
	}
	for _, searchword := range targetlist.Customizesyntax.Fofa {
		if searchword != "" {
			searchlist = append(searchlist, searchword)
		}
	}
	return searchlist

	return nil
}

func HunterMakeKeyword(targetconfig *config.Targetconfig) []string {
	return nil
}
