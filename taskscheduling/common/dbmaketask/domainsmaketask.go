package dbmaketask

import (
	"Findyou.TaskScheduling/common/db/mysqldb"
	"Findyou.TaskScheduling/common/db/redisdb"
	"Findyou.TaskScheduling/common/makekeywords"
	"Findyou.TaskScheduling/common/taskstruct"
	"Findyou.TaskScheduling/common/utils"
	"github.com/projectdiscovery/gologger"
	"strconv"
)

func Domainsmaketask(appconfig *taskstruct.Appconfig, targetconfig *taskstruct.Targetconfig) error {
	rediscon := redisdb.GetRedisClient()
	var fofakeywords []string
	var subdomainbrute []string
	var hunterkeywords []string
	var quakekeywords []string
	var splitslice [][]string
	waitdomains, err := mysqldb.GetAllDomains("Waiting", true)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return err
	}
	if len(waitdomains) == 0 {
		return nil
	}
	//生成搜索语句keywords和subdomainbrute列表
	for _, domainstruct := range waitdomains {
		if targetconfig.OtherSet.DomainSearch {
			keyword := makekeywords.Makekeywordfromdb(appconfig, targetconfig, domainstruct.RootDomain, "Domains", domainstruct.CompanyID)
			fofakeywords = append(fofakeywords, keyword.FofaKeyWord)
			hunterkeywords = append(hunterkeywords, keyword.HunterKeyWords...)
			quakekeywords = append(quakekeywords, keyword.QuakeKeyWords...)
		}
		//生成domainbrute列表
		subdomainbrute = append(subdomainbrute, domainstruct.RootDomain+"Findyou"+strconv.Itoa(int(domainstruct.CompanyID)))
	}
	subdomainbrute = utils.RemoveDuplicateElement(subdomainbrute)
	//keywords逻辑
	if len(fofakeywords) != 0 {
		fofakeywords = utils.RemoveDuplicateElement(fofakeywords)
		//写入keywords到tasks，状态waitting
		keywordtasks, err := mysqldb.WriteStringListToTasks(fofakeywords, "FOFASEARCH")
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		//如果fofakeywords和keywordtasks长度不一样，说明有部分fofakeyword之前写入过，所以要重新生成一个keyword
		if len(keywordtasks) != len(fofakeywords) {
			fofakeywords = []string{}
			for _, keywordtask := range keywordtasks {
				fofakeywords = append(fofakeywords, keywordtask.Task+"Findyou"+strconv.Itoa(int(keywordtask.CompanyID)))
			}
		}
		//处理keywords
		if len(keywordtasks) != 0 {
			//写入处理过的纯keywords到keywords表
			keywords := utils.TaskDataToKeywordData(fofakeywords)
			err = mysqldb.WriteDataToKeywords(keywords)
			if err != nil {
				gologger.Error().Msg(err.Error())
			}
			if len(fofakeywords) <= 100 {
				err = redisdb.WriteDataToRedis(rediscon, "FOFASEARCH", fofakeywords)
				if err != nil {
					gologger.Error().Msgf("Error writing data to Redis:", err)
					return err
				}
			} else {
				splitslice = utils.SplitSlice(fofakeywords, len(fofakeywords)/appconfig.Splittodb.Fofakeyword+1)
				for i := 0; i < len(splitslice); i++ {
					err = redisdb.WriteDataToRedis(rediscon, "FOFASEARCH", splitslice[i])
					if err != nil {
						gologger.Error().Msgf("Error writing data to Redis:", err)
						return err
					}
				}
			}
			for _, keyword := range keywordtasks {
				err = mysqldb.UpdateTasksStatus(keyword, "Pending")
				if err != nil {
					gologger.Error().Msg(err.Error())
				}
			}
		}

	}
	//处理domain爆破
	if len(subdomainbrute) != 0 {
		//遍历每个domain并写入subdomainbrute到tasks，状态waitting
		domaintasks, err := mysqldb.WriteStringListToTasks(subdomainbrute, "SUBDOMAINBRUTE")
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
		//判断是否已经生成过任务了
		if domaintasks != nil {
			//如果domaintask和subdomainbrute长度不一样，说明有部分subdomainbrute之前写入过，所以要重新生成一个domaintask
			if len(subdomainbrute) != len(domaintasks) {
				subdomainbrute = []string{}
				for _, domaintask := range domaintasks {
					subdomainbrute = append(subdomainbrute, domaintask.Task+"Findyou"+strconv.Itoa(int(domaintask.CompanyID)))
				}
			}
			//遍历每个domain并生成爆破任务
			for _, eachdomain := range subdomainbrute {
				var eachdomainlist []string
				eachdomainlist = append(eachdomainlist, eachdomain)
				err = redisdb.WriteDataToRedis(rediscon, "SUBDOMAINBRUTE", eachdomainlist)
				if err != nil {
					gologger.Error().Msgf("Error writing data to Redis:", err)
					return err
				}
			}
			for _, domain := range domaintasks {
				err = mysqldb.UpdateTasksStatus(domain, "Pending")
				if err != nil {
					gologger.Error().Msg(err.Error())
				}
			}
		}
	}
	//修改数据库中domain状态
	for _, domain := range waitdomains {
		err = mysqldb.UpdateDomainsStatus(domain, "Completed")
		if err != nil {
			gologger.Error().Msg(err.Error())
		}
	}
	gologger.Info().Msgf("[%d] 个domain已生成 [%d] 个任务", len(waitdomains), len(splitslice)+len(subdomainbrute))
	return nil
}
