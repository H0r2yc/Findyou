package config

import (
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
