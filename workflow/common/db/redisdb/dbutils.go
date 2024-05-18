package redisdb

import (
	"Findyou.WorkFlow/common/workflowstruct"
	"encoding/json"
	"github.com/projectdiscovery/gologger"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/context"
	"strings"
)

// 从 Redis 中取出元素并返回解码后的值
func GetFromRedis(rediscon *redis.Client, appconfig *workflowstruct.Appconfig) (string, []string, error) {
	// 初始化 context
	ctx := context.Background()
	// 获取所有键
	keys, err := rediscon.Keys(ctx, "*").Result()
	if err != nil {
		return "", nil, err
	}

	// 遍历所有键
	for _, key := range keys {
		// 检查键名是否为 "POCSCAN"
		if key == "POCSCAN" {
			continue
		}
		if key == "FOFASEARCH" {
			if !appconfig.OnlineAPI.IsFofa {
				continue
			}
		}
		if key == "HUNTERSEARCH" {
			if !appconfig.OnlineAPI.IsHunter {
				continue
			}
		}
		if key == "QUAKESEARCH" {
			if !appconfig.OnlineAPI.IsQuake {
				continue
			}
		} // 执行 LPOP
		val, err := rediscon.LPop(context.Background(), key).Result()
		if err != nil {
			return "", nil, err
		}
		// 将值进行 JSON 解码
		var data []string
		err = json.Unmarshal([]byte(val), &data)
		//这儿还没搞懂为什么数据多就直接返回了一个string而不是[]string
		if len(data) == 1 && strings.Contains(data[0], ",") {
			data = strings.Split(val, ",")
		}
		if err != nil {
			return "", nil, err
		}
		return key, data, nil
	}
	return "", nil, nil
}

func RedisIsNull() bool {
	db := GetRedisClient()
	result := db.DBSize(context.Background())
	if result.Err() != nil {
		gologger.Error().Msg("Get Redis DB Size Failed")
		return false
	}
	if size := result.Val(); size == 0 {
		return true
	} else {
		return false
	}
}
