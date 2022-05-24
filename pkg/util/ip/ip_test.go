package ip

import (
	"testing"
)

func TestGetLoopbackIP(t *testing.T) {
	lo4, err := GetLoopbackIP(false)
	if err != nil {
		t.Errorf("failed to get ipv4 loopback address: %v", err)
	}
	t.Logf("got ipv4 loopback address: %s", lo4)
	if lo4 != "127.0.0.1" {
		t.Errorf("got ipv4 loopback addr: '%s', expect: '127.0.0.1'", lo4)
	}

	lo6, err := GetLoopbackIP(true)
	if err != nil {
		t.Errorf("failed to get ipv6 loopback address: %v", err)
	}
	if lo6 != "" {
		// dual stack env
		t.Logf("got ipv6 loopback address: %s", lo6)
		if lo6 != "::1" {
			t.Errorf("got ipv6 loopback addr: '%s', expect: '::1'", lo6)
		}
	}
}
