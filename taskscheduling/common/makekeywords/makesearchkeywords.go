package makekeywords

import (
	"Findyou.TaskScheduling/common/db/mysqldb"
	"Findyou.TaskScheduling/common/taskstruct"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"strconv"
	"strings"
)

func makekeywordfromyaml(appconfig *taskstruct.Appconfig, targetconfig *taskstruct.Targetconfig) mysqldb.KeywordsList {
	var Keywords mysqldb.KeywordsList
	if targetconfig.OtherSet.DBScan {
		gologger.Info().Msg("跳过从配置文件生成keywords步骤")
		return Keywords
	}
	if appconfig.OnlineAPI.Fofa {
		Keywords.FofaKeyWords = FofaMakeKeyword(targetconfig)
	}
	if appconfig.OnlineAPI.Hunter {
		Keywords.HunterKeyWords = HunterMakeKeyword(targetconfig)
	}
	if appconfig.OnlineAPI.Quake {
		Keywords.QuakeKeyWords = QuakeMakeKeyword(targetconfig)
	}
	return Keywords
}

func Makekeywordfromdb(appconfig *taskstruct.Appconfig, targetconfig *taskstruct.Targetconfig, data, datatype string, companyid uint) mysqldb.KeywordsList {
	var Keywords mysqldb.KeywordsList
	if appconfig.OnlineAPI.Fofa {
		Keywords.FofaKeyWord = DBFOFAMakeKeyword(targetconfig, data, datatype, companyid)
	}
	if appconfig.OnlineAPI.Hunter {
		Keywords.HunterKeyWords = HunterMakeKeyword(targetconfig)
	}
	if appconfig.OnlineAPI.Quake {
		Keywords.QuakeKeyWords = QuakeMakeKeyword(targetconfig)
	}
	return Keywords
}

func DBFOFAMakeKeyword(targetconfig *taskstruct.Targetconfig, data, datatype string, companyid uint) string {
	//判断如果ip属于定义的归属地，那么就直接/24，如果不是那么就下面
	var searchlist []string
	if datatype == "IP" {
		for _, globalkeyword := range targetconfig.Target.Gobal_keywords {
			//Todo 如果是归属地相同或者重点ip表中，那么就直接/24
			if globalkeyword != "" {
				searchlist = append(searchlist, fmt.Sprintf("ip=\"%s/24\" && title=\"%s\" && country=\"CN\" && region!=\"HK\" && region!=\"TW\"", data, globalkeyword))
			} else {
				//TODO 根据cert或者iconhash等等做匹配
				searchlist = append(searchlist, fmt.Sprintf("ip=\"%s/24\" && title=\"系统\" && country=\"CN\" && region!=\"HK\" && region!=\"TW\"", data))
			}
		}
		return "(" + strings.Join(searchlist, ") || (") + ")Findyou" + strconv.Itoa(int(companyid))
	} else if datatype == "Domains" {
		searchlist = append(searchlist, fmt.Sprintf("domain=\"%s\" && country=\"CN\" && region!=\"HK\" && region!=\"TW\"", data))
		return "(" + strings.Join(searchlist, ") || (") + ")Findyou" + strconv.Itoa(int(companyid))
	}
	return ""
}

func FofaMakeKeyword(targetlist *taskstruct.Targetconfig) []string {
	var searchlist []string
	var keyword string
	database := mysqldb.GetDB()
	if database == nil {
		gologger.Error().Msg("获取数据库连接失败")
	}
	for _, name := range targetlist.Target.Name {
		if name != "" {
			keyword = fmt.Sprintf("cert=\"%s\"Findyou%d", name, taskstruct.CompanyID[name])
			searchlist = append(searchlist, keyword)
			keyword = fmt.Sprintf("title=\"%s\" && title=\"系统\"Findyou%d", name, taskstruct.CompanyID[name])
			searchlist = append(searchlist, keyword)
		}
	}
	for _, ipcompany := range targetlist.Target.IP {
		if ipcompany != "" {
			data := strings.SplitN(ipcompany, ":", 2)
			keyword = fmt.Sprintf("ip=\"%s/24\"Findyou%d", data[0], taskstruct.CompanyID[data[1]])
			searchlist = append(searchlist, keyword)

		}
	}

	for _, domain := range targetlist.Target.Domain {
		if domain != "" {
			data := strings.SplitN(domain, ":", 2)
			keyword = fmt.Sprintf("domain=\"%s\"Findyou%d", data[0], taskstruct.CompanyID[data[1]])
			searchlist = append(searchlist, keyword)
			keyword = fmt.Sprintf("host=\"%s\"Findyou%d", data[0], taskstruct.CompanyID[data[1]])
			searchlist = append(searchlist, keyword)
			keyword = fmt.Sprintf("cert=\"%s\"Findyou%d", data[0], taskstruct.CompanyID[data[1]])
			searchlist = append(searchlist, keyword)
		}
	}
	for _, cert := range targetlist.Target.Cert {
		if cert != "" {
			data := strings.SplitN(cert, ":", 2)
			keyword = fmt.Sprintf("cert=\"%s\"Findyou%d", data[0], taskstruct.CompanyID[data[1]])
			searchlist = append(searchlist, keyword)

		}
	}
	for _, searchword := range targetlist.Customizesyntax.Fofa {
		if searchword != "" {
			keyword = searchword
			searchlist = append(searchlist, keyword)
		}
	}
	return searchlist
}

func HunterMakeKeyword(targetconfig *taskstruct.Targetconfig) string {
	return "nil"
}

func QuakeMakeKeyword(targetconfig *taskstruct.Targetconfig) string {
	return "nil"
}
