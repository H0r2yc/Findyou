package redisdb

import (
	"Findyou.TaskScheduling/common/utils"
	"github.com/projectdiscovery/gologger"
	"github.com/redis/go-redis/v9"
	"golang.org/x/net/context"
	"sync"
	"time"
)

var (
	globalRedisClient *redis.Client
	redisMutex        sync.Mutex
)

func GetRedisClient() *redis.Client {
	redisMutex.Lock()
	defer redisMutex.Unlock()
	if globalRedisClient != nil {
		return globalRedisClient
	}
	const MAXRETRYNUMBER = 5
	const RetriedSleepTime = 5 * time.Second
	RetriedCount := 0
	for {
		if RetriedCount > MAXRETRYNUMBER {
			gologger.Error().Msg("Failed to connect Redis")
			return nil
		}
		globalRedisClient = getRedisClient()
		if globalRedisClient == nil {
			gologger.Error().Msg("Connect to Redis failed, retry...")
			RetriedCount++
			time.Sleep(RetriedSleepTime)
			continue
		}
		return globalRedisClient
	}
}

func getRedisClient() *redis.Client {
	database := utils.GetAppConf()
	options := &redis.Options{
		Addr:     database.Redis.Host,
		Password: database.Redis.Password, // no password set
		DB:       0,                       // use default DB
	}

	client := redis.NewClient(options)

	// Test the connection to Redis
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		gologger.Error().Msgf("Error connecting to Redis: %v\n", err)
		return nil
	}
	return client
}

// CloseRedisClient explicitly closes a Redis client connection
func CloseRedisClient(client *redis.Client) {
	if client == nil {
		return
	}
	if err := client.Close(); err != nil {
		gologger.Error().Msgf("Error closing Redis client: %v\n", err)
	}
	gologger.Info().Msg("Redis connection closed")
}
