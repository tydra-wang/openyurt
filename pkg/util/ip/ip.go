package ip

import (
	"net"
	"strings"

	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

const (
	DefaultLoopbackIP4 = "127.0.0.1"
	DefaultLoopbackIP6 = "::1"
)

// MustGetLoopbackIP is a wrapper for GetLoopbackIP. If any error occurs or loopback interface is not found,
// will fall back to 127.0.0.1 for ipv4 or ::1 for ipv6.
func MustGetLoopbackIP(wantIPv6 bool) string {
	ip, err := GetLoopbackIP(wantIPv6)
	if err != nil {
		klog.Errorf("failed to get loopback addr: %v", err)
	}
	if ip != "" {
		return ip
	}
	if wantIPv6 {
		return DefaultLoopbackIP6
	}
	return DefaultLoopbackIP4
}

// GetLoopbackIP returns the ip address of local loopback interface.
func GetLoopbackIP(wantIPv6 bool) (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && ipnet.IP.IsLoopback() && wantIPv6 == utilnet.IsIPv6(ipnet.IP) {
			return ipnet.IP.String(), nil
		}
	}
	return "", nil
}

func JoinIPStrings(ips []net.IP) string {
	var strs []string
	for _, ip := range ips {
		strs = append(strs, ip.String())
	}
	return strings.Join(strs, ",")
}
