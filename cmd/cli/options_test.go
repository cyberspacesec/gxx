package cli

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestHelpPrintsUsageOnce(t *testing.T) {
	for _, arg := range []string{"-h", "-help", "--help"} {
		var out bytes.Buffer
		_, err := ParseCmdOptions([]string{arg}, &out)
		if !errors.Is(err, ErrHelp) {
			t.Fatalf("%s: err=%v, want ErrHelp", arg, err)
		}
		if n := strings.Count(out.String(), "用法:"); n != 1 {
			t.Fatalf("%s: 用法输出了 %d 次:\n%s", arg, n, out.String())
		}
	}
}

func TestUnknownFlagReturnsErrorWithoutUsage(t *testing.T) {
	var out bytes.Buffer
	_, err := ParseCmdOptions([]string{"-bogus"}, &out)
	if err == nil || errors.Is(err, ErrHelp) {
		t.Fatalf("err=%v, want parse error", err)
	}
	if !strings.Contains(err.Error(), "-bogus") || !strings.Contains(err.Error(), "-h") {
		t.Fatalf("错误信息应指出未知参数并提示 -h: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("解析失败不应输出完整用法:\n%s", out.String())
	}
}

// 目标按原样保留：URL 路径大小写敏感，'#' 也可能是目标的一部分。
func TestTargetsKeepCaseAndFragment(t *testing.T) {
	var out bytes.Buffer
	options, err := ParseCmdOptions([]string{
		"-u", "https://Example.com/Admin#Top, 'http://b.example/X'",
		"-url", `"https://c.example/Path"`,
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://Example.com/Admin#Top", "http://b.example/X", "https://c.example/Path"}
	if !slices.Equal(options.Target, want) {
		t.Fatalf("targets=%q, want %q", options.Target, want)
	}
}

func TestOutputExtensionValidation(t *testing.T) {
	cases := []struct {
		args []string
		ok   bool
	}{
		{[]string{"-u", "a", "-o", "r.txt"}, true},
		{[]string{"-u", "a", "-o", "r.CSV"}, true},
		{[]string{"-u", "a", "-o", "r.json"}, true},
		{[]string{"-u", "a", "-o", "r.jsonl"}, true},
		{[]string{"-u", "a", "-o", "r.xml"}, false},
		{[]string{"-u", "a", "-o", "r.xml", "-json"}, true},
		{[]string{"-u", "a", "-sock", "out.txt"}, false},
		{[]string{"-o", "r.txt"}, false}, // 缺少目标
	}
	for _, c := range cases {
		var out bytes.Buffer
		_, err := ParseCmdOptions(c.args, &out)
		if (err == nil) != c.ok {
			t.Errorf("%q: err=%v, want ok=%v", c.args, err, c.ok)
		}
	}
}

func TestInvalidNumbersFallBackToDefaults(t *testing.T) {
	var out bytes.Buffer
	options, err := ParseCmdOptions([]string{"-u", "a", "-t", "0", "-rt", "-1", "-timeout", "0"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if options.Threads != defaultThreads || options.RuleThreads != defaultRuleThreads || options.Timeout != defaultTimeout {
		t.Fatalf("got threads=%d rule=%d timeout=%d", options.Threads, options.RuleThreads, options.Timeout)
	}
}
