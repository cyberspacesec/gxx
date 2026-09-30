package wappalyzer

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"regexp/syntax"
	"strings"
	"sync"
	"testing"
	"unicode"

	upstream "github.com/projectdiscovery/wappalyzergo"
)

func TestLiteralIndexAgainstContains(t *testing.T) {
	words := []string{"he", "she", "his", "hers", "a", "aa", "aaa", "/wp-content/", "", "ABC"}
	words = append(words[:8], words[9:]...)
	idx := newLiteralIndex(words)
	bits := make([]uint64, (len(words)+63)/64)
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 1000; i++ {
		var input strings.Builder
		for j := 0; j < 30; j++ {
			input.WriteString(words[rng.Intn(len(words))])
			input.WriteByte(byte(rng.Intn(256)))
		}
		data := input.String()
		idx.match(data, bits)
		for id, word := range words {
			if got, want := bits[id/64]&(uint64(1)<<uint(id%64)) != 0, strings.Contains(data, word); got != want {
				t.Fatalf("word=%q input=%q got=%t want=%t", word, data, got, want)
			}
		}
	}
}

func TestFilterPreservesEveryASCIIFoldClass(t *testing.T) {
	for ascii := rune(0); ascii < 128; ascii++ {
		want := strings.ToLower(string(ascii))
		for folded := unicode.SimpleFold(ascii); folded != ascii; folded = unicode.SimpleFold(folded) {
			if got := normalizeForFilter(string(folded)); got != want {
				t.Fatalf("ASCII=%U folded=%U got=%q want=%q", ascii, folded, got, want)
			}
		}
	}
}

// 正例由原模式语法树生成，再通过上游解析器判定；不把预筛选自身的输出当作真值。
func patternWitness(re *syntax.Regexp, alternate int) string {
	switch re.Op {
	case syntax.OpLiteral:
		return string(re.Rune)
	case syntax.OpCharClass:
		if len(re.Rune) > 0 {
			return string(re.Rune[0])
		}
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return "a"
	case syntax.OpCapture, syntax.OpPlus:
		return patternWitness(re.Sub[0], alternate)
	case syntax.OpQuest, syntax.OpStar:
		if alternate%2 != 0 {
			return patternWitness(re.Sub[0], alternate)
		}
	case syntax.OpRepeat:
		if re.Min <= 250 {
			return strings.Repeat(patternWitness(re.Sub[0], alternate), re.Min)
		}
	case syntax.OpConcat:
		var b strings.Builder
		for _, sub := range re.Sub {
			b.WriteString(patternWitness(sub, alternate))
		}
		return b.String()
	case syntax.OpAlternate:
		return patternWitness(re.Sub[alternate%len(re.Sub)], alternate)
	}
	return ""
}

func TestAllHTTPPatternsConservativeFilter(t *testing.T) {
	var data upstream.Fingerprints
	if err := json.Unmarshal([]byte(upstream.GetRawFingerprints()), &data); err != nil {
		t.Fatal(err)
	}
	sources := make(map[string]struct{})
	for _, f := range data.Apps {
		for _, source := range f.Headers {
			sources[source] = struct{}{}
		}
		for _, source := range f.Cookies {
			sources[source] = struct{}{}
		}
		for _, source := range f.HTML {
			sources[source] = struct{}{}
		}
		for _, source := range f.ScriptSrc {
			sources[source] = struct{}{}
		}
		for _, patterns := range f.Meta {
			for _, source := range patterns {
				sources[source] = struct{}{}
			}
		}
	}
	verified, filtered := 0, 0
	for source := range sources {
		literals := requiredLiterals(source)
		if len(literals) == 0 {
			continue
		}
		filtered++
		pattern, err := upstream.ParsePattern(source)
		if err != nil {
			continue
		}
		expression, _, _ := strings.Cut(source, `\;`)
		tree, err := syntax.Parse("(?i)"+expression, syntax.Perl)
		if err != nil {
			continue
		}
		for variant := 0; variant < 16; variant++ {
			witness := patternWitness(tree, variant)
			if len(witness) > 1<<20 {
				continue
			}
			for _, text := range []string{witness, strings.ToLower(witness), strings.ToUpper(witness), strings.ReplaceAll(strings.ToLower(witness), "s", "ſ")} {
				if matched, _ := pattern.Evaluate(text); !matched {
					continue
				}
				verified++
				text = normalizeForFilter(text)
				present := false
				for _, literal := range literals {
					present = present || strings.Contains(text, literal)
				}
				if !present {
					t.Fatalf("预筛选漏匹配: pattern=%q literals=%q text=%q", source, literals, text)
				}
			}
		}
	}
	t.Logf("HTTP 模式=%d 可预筛选=%d 上游确认正例=%d", len(sources), filtered, verified)
	if verified < 1000 {
		t.Fatal("正例覆盖不足")
	}
}

func TestHTTPMatcherUpstreamParity(t *testing.T) {
	m, err := newHTTPMatcher(upstream.GetRawFingerprints())
	if err != nil {
		t.Fatal(err)
	}
	reference, err := upstream.New()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		header map[string][]string
		body   string
	}{
		{nil, ""},
		{map[string][]string{"Server": {"Apache/2.4.62"}, "X-Powered-By": {"PHP/8.3.0"}}, `<meta name="generator" content="WordPress 6.8"><script src="/wp-includes/js/jquery.js"></script>`},
		{map[string][]string{"Server": {"nginx/1.28.0"}}, `<html><title>普通页面</title><body>没有技术特征</body></html>`},
		{nil, `<meta name="generator" content="Drupal 10"><script src="/misc/drupal.js"></script>`},
		{nil, `<meta name="generator" content="Joomla! - Open Source Content Management" />`},
		{map[string][]string{"Set-Cookie": {"laravel_session=abc; Path=/; HttpOnly", "XSRF-TOKEN=xyz; Path=/"}}, `<html>Laravel</html>`},
		{map[string][]string{"Server": {"cloudflare"}, "CF-RAY": {"abc"}}, `<script src="https://cdn.jsdelivr.net/npm/vue@3/dist/vue.js"></script>`},
		{map[string][]string{"X-Jenkins": {"2.440.1"}}, `<html>Jenkins</html>`},
		{nil, `<script src="https://cdn.example.com/jquery-3.7.1.min.js"></script><script src="/bootstrap.min.js"></script>`},
		{nil, `<html ng-app="app"><script src="/angular.min.js"></script><meta name="generator" content="Ghost 5.0"></html>`},
		{nil, `<script type="application/json">{"x":"<meta name='generator' content='Drupal'>"}</script><script>window.test=1</script>`},
		{nil, `<meta name="generator" content="WordPre&#x53;s 6.8"><script src="/JQUERY&#x2e;JS"></script>`},
		{nil, `<meta name="generator" content="Wordpreſs 6.8">`},
		{nil, string([]byte{0xff, '<', 'b', '>', 0xc0, 0xaf})},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			want := reference.FingerprintWithInfo(tc.header, []byte(tc.body))
			got := m.FingerprintWithInfo(tc.header, []byte(tc.body))
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got=%+v\nwant=%+v", got, want)
			}
		})
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, tc := range cases {
				m.FingerprintWithInfo(tc.header, []byte(tc.body))
			}
		}()
	}
	wg.Wait()
}

func TestHTTPMatcherConfidenceAndImplications(t *testing.T) {
	rules := `{"apps":{"A":{"cats":[1],"headers":{"server":"a\\;confidence:0"},"html":["a\\;confidence:0","b\\;confidence:50"],"meta":{"generator":["(?-i:Case)\\;confidence:0","case\\;confidence:50"]},"scriptSrc":["script\\;version:1"],"implies":["B"]},"B":{"cats":[27]}}}`
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte(rules), 0600); err != nil {
		t.Fatal(err)
	}
	reference, err := upstream.NewFromFile(path, false, false)
	if err != nil {
		t.Fatal(err)
	}
	m, err := newHTTPMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"a", "ab", `<meta name="generator" content="&#x43;ase">`, `<meta name="generator" content="case"/>`, `<script src="&#x53;CRIPT.js"></script>`, `<script src="ſcript.js"></script>`} {
		got, want := m.FingerprintWithInfo(nil, []byte(body)), reference.FingerprintWithInfo(nil, []byte(body))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("body=%q got=%+v want=%+v", body, got, want)
		}
	}
}

func TestHTTPMatcherCacheEvictionPreservesRules(t *testing.T) {
	rules := upstream.Fingerprints{Apps: make(map[string]*upstream.Fingerprint)}
	for i := 0; i < 600; i++ {
		rules.Apps[fmt.Sprintf("app-%d", i)] = &upstream.Fingerprint{Headers: map[string]string{fmt.Sprintf("x-test-%d", i): "match"}}
	}
	// 使用不同表达式填满编译缓存，元信息及规则索引在淘汰前后保持完整。
	for name, rule := range rules.Apps {
		for key := range rule.Headers {
			rule.Headers[key] = name
		}
	}
	data, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	m, err := newHTTPMatcher(string(data))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 601; i++ {
		n := i % 600
		name := fmt.Sprintf("app-%d", n)
		got := m.FingerprintWithInfo(map[string][]string{fmt.Sprintf("x-test-%d", n): {name}}, nil)
		if _, ok := got[name]; !ok || len(got) != 1 {
			t.Fatalf("淘汰后规则丢失: %d %+v", n, got)
		}
	}
	if size := m.programs.Len(); size > 512 {
		t.Fatalf("缓存越界: %d", size)
	}
}
