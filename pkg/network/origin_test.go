package network

import (
	"net/url"
	"slices"
	"testing"
)

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"http://a.com", "http://a.com/login?x=1", true},
		{"http://a.com", "http://A.COM:80/", true},
		{"https://a.com", "https://a.com:443/x", true},
		{"http://a.com.", "http://a.com", true},
		{"http://[::1]:8080/", "http://[::1]:8080/x", true},
		{"http://a.com", "https://a.com", false},
		{"http://a.com", "http://www.a.com", false},
		{"http://a.com", "http://a.com:8080", false},
		{"https://a.com", "https://a.com:8443", false},
		{"http://a.com", "ftp://a.com", false},
		{"http://a.com", "/relative", false},
	}
	for _, c := range cases {
		a, _ := url.Parse(c.a)
		b, _ := url.Parse(c.b)
		if got := SameOrigin(a, b); got != c.want {
			t.Errorf("SameOrigin(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
	if SameOrigin(nil, nil) {
		t.Error("nil 不属于任何资产")
	}
}

func TestTargetCandidates(t *testing.T) {
	cases := []struct {
		target   string
		want     []string
		samePort bool
	}{
		{"http://a.com/x", []string{"http://a.com/x"}, true},
		{"https://a.com", []string{"https://a.com"}, true},
		{"a.com", []string{"https://a.com", "http://a.com"}, false},
		{"a.com/path", []string{"https://a.com/path", "http://a.com/path"}, false},
		{"a.com:80", []string{"http://a.com:80"}, true},
		{"a.com:443", []string{"https://a.com:443"}, true},
		{"1.2.3.4:8080", []string{"https://1.2.3.4:8080", "http://1.2.3.4:8080"}, true},
		{"[::1]:9000", []string{"https://[::1]:9000", "http://[::1]:9000"}, true},
		{"  ", nil, false},
	}
	for _, c := range cases {
		got, samePort := TargetCandidates(c.target)
		if !slices.Equal(got, c.want) || samePort != c.samePort {
			t.Errorf("TargetCandidates(%q) = %v, %v; want %v, %v", c.target, got, samePort, c.want, c.samePort)
		}
	}
}
