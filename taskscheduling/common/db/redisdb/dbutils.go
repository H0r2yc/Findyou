package redisdb

import (
	"encoding/json"
	"github.com/projectdiscovery/gologger"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/context"
)

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
		gologger.Info().Msgf("还有 %d 任务待执行\n", size)
		return false
	}
}

func WriteDataToRedis(db *redis.Client, key string, data []string) error {
	// 将 []string 转换为 JSON 格式
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	// 创建 Redis 列表的命令
	err = db.RPush(context.Background(), key, jsonData).Err()
	if err != nil {
		return err
	}
	return nil
}

func IsDataInSet(rediscon *redis.Client, key string, data []string) (bool, error) {
	ctx := context.Background()
	jsonData, err := json.Marshal(data)
	if err != nil {
		return false, err
	}
	// 获取列表中的所有元素
	items, err := rediscon.LRange(ctx, key, 0, -1).Result()
	if err != nil {
		return false, err
	}
	// 遍历元素以检查数据是否存在
	for _, item := range items {
		if item == string(jsonData) {
			return true, nil
		}
	}
	return false, nil
}
