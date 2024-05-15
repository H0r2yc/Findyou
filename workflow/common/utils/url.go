package utils

import (
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
		if proxy := GetProxyConfig(); proxy != "" {
			proxyURL, parseErr := url.Parse(proxy)
			if parseErr != nil {
				log.Println("proxy workflowstruct fail:%v,skip proxy!", parseErr)
				log.Println("proxy workflowstruct fail:%v,skip proxy!", parseErr)
			} else {
				transport = &http.Transport{
					Proxy:           http.ProxyURL(proxyURL),
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}
			}
		} else {
			log.Println("get proxy workflowstruct fail or disabled by worker,skip proxy!")
			log.Println("get proxy workflowstruct fail or disabled by worker,skip proxy!")
		}
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
	}
	return httpClient
}
