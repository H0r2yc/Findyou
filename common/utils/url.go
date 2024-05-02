package utils

import (
	"Findyou/common/config"
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"time"
)

// GetProxyHttpClient 获取代理的http client
func GetProxyHttpClient(isProxy bool) *http.Client {
	var transport *http.Transport
	transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if isProxy {
		if proxy := config.GetProxyConfig(); proxy != "" {
			proxyURL, parseErr := url.Parse(proxy)
			if parseErr != nil {
				log.Println("proxy config fail:%v,skip proxy!", parseErr)
				log.Println("proxy config fail:%v,skip proxy!", parseErr)
			} else {
				transport = &http.Transport{
					Proxy:           http.ProxyURL(proxyURL),
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}
			}
		} else {
			log.Println("get proxy config fail or disabled by worker,skip proxy!")
			log.Println("get proxy config fail or disabled by worker,skip proxy!")
		}
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
	}
	return httpClient
}
