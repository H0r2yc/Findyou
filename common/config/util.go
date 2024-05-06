package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// getCIDR 函数用于获取 IP 的 C 段地址
func GetCIDR(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) >= 3 {
		cidr := strings.Join(parts[:3], ".") + "."
		return cidr
	} else {
		//gologger.Error().Msgf("Error: parts slice length is less than 3: %v", parts)
		return ""
	}
}

// GetFirstSubdomain 获取 URL 的第一个子域名
func GetFirstSubdomain(u string) (string, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	//获取不含端口的ip
	hostname, _, err := net.SplitHostPort(parsedURL.Host)
	if err != nil {
		// 如果没有端口，则 SplitHostPort 会返回错误，可以忽略这个错误
		hostname = parsedURL.Host
	}
	// 判断 URL 是否为 IP 地址
	if net.ParseIP(hostname) != nil {
		return "", fmt.Errorf("URL is an IP address")
	}

	// 解析域名
	domainParts := strings.Split(parsedURL.Hostname(), ".")
	if len(domainParts) < 2 {
		return "", fmt.Errorf("Invalid domain")
	}

	// 返回第一个子域名
	return domainParts[0], nil
}
