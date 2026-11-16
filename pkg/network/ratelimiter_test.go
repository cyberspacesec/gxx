package network

import "testing"

func TestLimiterKey(t *testing.T) {
	for _, c := range []struct {
		target        string
		host, perPort string
	}{
		{"https://A.com/x", "a.com", "a.com:443"},
		{"https://a.com:443", "a.com", "a.com:443"},
		{"http://a.com", "a.com", "a.com:80"},
		{"http://a.com:8080/p?q=1", "a.com", "a.com:8080"},
		{"10.0.0.1:6379", "10.0.0.1", "10.0.0.1:6379"},
		{"http://[::1]:8443/", "::1", "[::1]:8443"},
		{"", "", ""},
	} {
		if got := limiterKey(c.target, false); got != c.host {
			t.Errorf("limiterKey(%q, false)=%q，期望 %q", c.target, got, c.host)
		}
		if got := limiterKey(c.target, true); got != c.perPort {
			t.Errorf("limiterKey(%q, true)=%q，期望 %q", c.target, got, c.perPort)
		}
	}
}
