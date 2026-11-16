package wappalyzer

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"regexp/syntax"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"unicode"
	"unicode/utf8"

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
		var literals []string
		if tree := parseUpstreamPattern(source); tree != nil {
			literals = literalsFromTree(tree)
		}
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

// 合取预筛选要求每一组都命中，比单组更严格；必须对全部上游模式证明它同样不会漏掉真实匹配。
// 正例由语法树生成并经上游判定，预筛选只读取与生产路径相同的归一化文本。
func TestAllHTTPPatternsConjunctiveFilterNeverExcludesMatch(t *testing.T) {
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
	verified, multiGroup := 0, 0
	for source := range sources {
		groups := requiredLiteralGroups(source)
		if len(groups) == 0 {
			continue
		}
		if len(groups) > 1 {
			multiGroup++
		}
		pattern, err := upstream.ParsePattern(source)
		if err != nil {
			continue
		}
		expression, _, _ := strings.Cut(source, `\;`)
		tree, err := syntax.Parse("(?i)"+expression, syntax.Perl)
		if err != nil {
			continue
		}
		p := &httpPattern{source: source, literalGroups: groups, literalIDs: make([][]int, len(groups))}
		for i, group := range groups {
			p.literalIDs[i] = make([]int, len(group))
		}
		for variant := 0; variant < 16; variant++ {
			witness := patternWitness(tree, variant)
			if len(witness) > 1<<20 {
				continue
			}
			for _, text := range []string{witness, strings.ToLower(witness), strings.ToUpper(witness), strings.ReplaceAll(strings.ToLower(witness), "s", "ſ"), "prefix " + witness + " suffix"} {
				if matched, _ := pattern.Evaluate(strings.ToLower(text)); !matched {
					continue
				}
				verified++
				if !p.mayMatch(nil, normalizeForFilter(strings.ToLower(text))) {
					t.Fatalf("合取预筛选漏匹配: pattern=%q groups=%q text=%q", source, groups, text)
				}
			}
		}
	}
	t.Logf("HTTP 模式=%d 多组模式=%d 上游确认正例=%d", len(sources), multiGroup, verified)
	if verified < 1000 || multiGroup < 500 {
		t.Fatalf("覆盖不足: 正例=%d 多组模式=%d", verified, multiGroup)
	}
}

// 位图路径与逐字符串查找路径必须得出相同结论，二者分别服务正文/脚本与 header/cookie/meta。
func TestMayMatchBitsAndContainsAgree(t *testing.T) {
	m, err := newHTTPMatcher(upstream.GetRawFingerprints())
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(7))
	var all []*httpPattern
	for _, g := range m.body.groups {
		all = append(all, g.patterns...)
	}
	for _, g := range m.scripts.groups {
		all = append(all, g.patterns...)
	}
	words := []string{"wp-content", "jquery", "react", "<link", " href=", "stylesheet", "/wp-includes/", "bootstrap", "angular", "vue", "tilda", "pure", ".css", ".js", "generator"}
	buffer := m.bits.Get().(*[]uint64)
	defer m.bits.Put(buffer)
	bits := *buffer
	for i := 0; i < 300; i++ {
		var b strings.Builder
		for n := rng.Intn(40); n > 0; n-- {
			b.WriteString(words[rng.Intn(len(words))])
			b.WriteByte(" <>/\"'="[rng.Intn(7)])
		}
		data := normalizeForFilter(strings.ToLower(b.String()))
		m.literals.match(data, bits)
		for _, p := range all {
			if a, c := p.mayMatch(bits, data), p.mayMatch(nil, data); a != c {
				t.Fatalf("两条路径结论不一致: pattern=%q data=%q bits=%v contains=%v", p.source, data, a, c)
			}
		}
	}
}

// 用接近真实网页的大小与结构对拍完整输出，覆盖合取过滤真正生效的场景：
// 页面同时出现部分字面量（如 "<link"）但不满足全部组。
func TestHTTPMatcherUpstreamParityRealisticPages(t *testing.T) {
	m, err := newHTTPMatcher(upstream.GetRawFingerprints())
	if err != nil {
		t.Fatal(err)
	}
	reference, err := upstream.New()
	if err != nil {
		t.Fatal(err)
	}
	fragments := []string{
		`<link rel="stylesheet" href="/static/css/app.css">`,
		`<link rel='stylesheet' id='wp-block-library-css' href='/wp-includes/css/dist/block-library/style.min.css'>`,
		`<link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css">`,
		`<link href="https://static.tildacdn.com/css/tilda-grid.css" rel="stylesheet">`,
		`<link rel="stylesheet" href="https://unpkg.com/purecss@2.0.6/build/pure-min.css">`,
		`<script src="/static/js/jquery-3.6.0.min.js"></script>`,
		`<script src="https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.js"></script>`,
		`<script src="/assets/react.production.min.js"></script>`,
		`<meta name="generator" content="WordPress 6.4.2">`,
		`<meta name="generator" content="Hugo 0.120.0">`,
		`<div class="container"><p>Powered by Discuz! X3.4</p></div>`,
		`<div id="app" data-v-app></div><span class="ng-scope">x</span>`,
		`<a href="/login">登录</a><span>版权所有 © 2026</span>`,
		`<p>` + strings.Repeat("lorem ipsum dolor sit amet ", 40) + `</p>`,
	}
	headers := []map[string][]string{
		nil,
		{"Server": {"nginx/1.24.0"}},
		{"Server": {"Apache/2.4.58 (Ubuntu)"}, "X-Powered-By": {"PHP/8.2.12"}},
		{"Set-Cookie": {"PHPSESSID=abc; path=/", "wordpress_test_cookie=WP+Cookie+check; path=/"}},
	}
	// 合取过滤是否生效取决于页面中出现哪些片段的组合，与页面大小无关；用大量小页面覆盖组合，
	// 只保留少量大页面。上游参照实现对每个页面都运行全部正则，开销远高于被测实现。
	// 本测试是单线程的，竞态检测无法从中发现问题（并发安全由 TestHTTPMatcherUpstreamParity 覆盖），
	// 因此 -race 与 -short 下缩减页面数，避免拖慢 CI 而不损失检测能力。
	pages := 200
	if raceEnabled || testing.Short() {
		pages = 20
	}
	rng := rand.New(rand.NewSource(20261105))
	for i := 0; i < pages; i++ {
		var b strings.Builder
		b.WriteString(`<!DOCTYPE html><html><head><title>页面</title>`)
		target := 1<<10 + rng.Intn(3<<10)
		if i%50 == 0 {
			target = 64 << 10
		}
		for b.Len() < target {
			b.WriteString(fragments[rng.Intn(len(fragments))])
			b.WriteByte('\n')
		}
		b.WriteString(`</body></html>`)
		header := headers[i%len(headers)]
		got := m.FingerprintWithInfo(header, []byte(b.String()))
		want := reference.FingerprintWithInfo(header, []byte(b.String()))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("第 %d 个页面（%d 字节）输出不一致:\ngot=%v\nwant=%v", i, b.Len(), keys(got), keys(want))
		}
	}
}

func keys(m map[string]upstream.AppInfo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
	// 模式按 (?i) 编译，长 s（ſ）与 s 属于同一大小写等价类，必须得到与 ASCII 写法
	// 相同的识别结果。上游 v0.3.9 的字面量检查不折叠长 s，会漏掉这一例。
	folded := m.FingerprintWithInfo(nil, []byte(`<meta name="generator" content="Wordpreſs 6.8">`))
	ascii := m.FingerprintWithInfo(nil, []byte(`<meta name="generator" content="Wordpress 6.8">`))
	if len(ascii) == 0 || !reflect.DeepEqual(keys(folded), keys(ascii)) {
		t.Fatalf("长 s 写法的识别结果不一致: folded=%v ascii=%v", keys(folded), keys(ascii))
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
	for _, body := range []string{"a", "ab", `<meta name="generator" content="&#x43;ase">`, `<meta name="generator" content="case"/>`, `<script src="script.js"></script>`} {
		got, want := m.FingerprintWithInfo(nil, []byte(body)), reference.FingerprintWithInfo(nil, []byte(body))
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("body=%q got=%+v want=%+v", body, got, want)
		}
	}
	// 实体解码会在已小写化的正文里重新产生大写字母（&#x53; → S），长 s（ſ）与 s
	// 属于同一大小写等价类。模式按 (?i) 编译，这两种写法都必须命中；上游 v0.3.9
	// 的脚本索引与字面量检查直接使用未折叠的文本，会漏掉它们。预筛选在归一化
	// 副本上进行，结果以正则语义为准。
	plain := m.FingerprintWithInfo(nil, []byte(`<script src="script.js"></script>`))
	for _, body := range []string{`<script src="&#x53;CRIPT.js"></script>`, `<script src="ſcript.js"></script>`} {
		if got := m.FingerprintWithInfo(nil, []byte(body)); len(plain) == 0 || !reflect.DeepEqual(got, plain) {
			t.Fatalf("等价写法的识别结果不一致: body=%q got=%+v plain=%+v", body, got, plain)
		}
	}
}

// 自有的模式编译与版本提取必须与上游解析器逐条一致：能否编译、置信度、
// 是否跳过正则，以及每个正例和反例的命中结论与版本。
func TestCompiledPatternMatchesUpstreamParser(t *testing.T) {
	var data upstream.Fingerprints
	if err := json.Unmarshal([]byte(upstream.GetRawFingerprints()), &data); err != nil {
		t.Fatal(err)
	}
	sources := map[string]struct{}{
		// 版本模板的三元表达式与无效写法。
		`a(b)?\;version:\1?yes:no`:      {},
		`a(b)?\;version:\1?:no`:         {},
		`a(b)?\;version:\1?yes:`:        {},
		`ab\;version:x?y?z`:             {},
		`ab\;version:x?y:z:w`:           {},
		`a(\d)b\;version: \1 `:          {},
		`ab\;confidence:abc\;version:1`: {},
		`ab\;confidence:30\;unknown`:    {},
		`\;confidence:50`:               {},
		`a\+b\*c+`:                      {},
		`(`:                             {},
	}
	for _, f := range data.Apps {
		for _, source := range f.Headers {
			sources[source] = struct{}{}
		}
		for _, source := range f.Cookies {
			sources[source] = struct{}{}
		}
		for _, list := range [][]string{f.HTML, f.ScriptSrc} {
			for _, source := range list {
				sources[source] = struct{}{}
			}
		}
		for _, patterns := range f.Meta {
			for _, source := range patterns {
				sources[source] = struct{}{}
			}
		}
	}
	compared, versions := 0, 0
	for source := range sources {
		reference, referenceErr := upstream.ParsePattern(source)
		compiled, err := compilePattern(source)
		if (err == nil) != (referenceErr == nil) {
			t.Fatalf("能否编译不一致: pattern=%q 自有=%v 上游=%v", source, err, referenceErr)
		}
		if err != nil {
			continue
		}
		if compiled.confidence != reference.Confidence || compiled.skipRegex != reference.SkipRegex || compiled.version != reference.Version {
			t.Fatalf("元数据不一致: pattern=%q 自有=%+v 上游=%+v", source, compiled, reference)
		}
		texts := []string{"", "ab", "abc", "a+b*ccc", "a5b", "no match here"}
		expression, _, _ := strings.Cut(source, `\;`)
		if tree, err := syntax.Parse("(?i)"+expression, syntax.Perl); err == nil {
			for variant := 0; variant < 8; variant++ {
				witness := patternWitness(tree, variant)
				if len(witness) <= 1<<16 {
					texts = append(texts, witness, strings.ToLower(witness), strings.ToUpper(witness), "prefix "+witness+" suffix")
				}
			}
		}
		for _, text := range texts {
			wantMatched, wantVersion := reference.Evaluate(text)
			gotMatched, gotVersion := compiled.evaluate(text)
			if gotMatched != wantMatched || gotVersion != wantVersion {
				t.Fatalf("判定不一致: pattern=%q text=%q 自有=(%t,%q) 上游=(%t,%q)", source, text, gotMatched, gotVersion, wantMatched, wantVersion)
			}
			compared++
			if wantVersion != "" {
				versions++
			}
		}
	}
	t.Logf("模式=%d 对照判定=%d 其中提取到版本=%d", len(sources), compared, versions)
	if compared < 100000 || versions < 1000 {
		t.Fatalf("覆盖不足: 判定=%d 版本=%d", compared, versions)
	}
}

func TestMatchSpan(t *testing.T) {
	for _, tc := range []struct {
		source   string
		windowed bool
	}{
		{`<link[^>]+wp-content`, true},
		{`jquery[.-]([\d.]*\d)[^/]*\.js\;version:\1`, true},
		{`powered by <a[^>]+>discuz`, true},
		// 位置断言会读取匹配区间之外的字符。
		{`^wordpress`, false},
		{`wordpress$`, false},
		{`\bwordpress\b`, false},
		// 显式的无界重复没有长度上限。
		{`wordpress{2,}`, false},
		// 嵌套重复的跨度超过窗口上限。
		{`(?:wordpress[^>]*)*`, false},
	} {
		if got := matchSpan(tc.source) > 0; got != tc.windowed {
			t.Errorf("matchSpan(%q) 可按窗口求值=%t，期望 %t", tc.source, got, tc.windowed)
		}
	}
}

func TestLiteralWindowsCoverEveryOccurrence(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	words := []string{"wp-content", "jquery", "中文"}
	for i := 0; i < 500; i++ {
		var b strings.Builder
		for b.Len() < 20000 {
			switch rng.Intn(40) {
			case 0:
				b.WriteString(words[rng.Intn(len(words))])
			case 1:
				b.WriteString("页面")
			default:
				b.WriteString("filler ")
			}
		}
		data := b.String()
		span := 16 + rng.Intn(400)
		chosen := words[:1+rng.Intn(len(words))]
		var buffer [maxWindows]textWindow
		windows, ok := literalWindows(buffer[:0], data, chosen, span)
		if !ok {
			continue
		}
		for index, window := range windows {
			if window.start >= window.end || !utf8.RuneStart(data[window.start]) || window.end < len(data) && !utf8.RuneStart(data[window.end]) {
				t.Fatalf("窗口未对齐字符边界: %+v", window)
			}
			if index > 0 && window.start <= windows[index-1].end {
				t.Fatalf("窗口未按起点升序且互不相交: %+v", windows)
			}
		}
		for _, word := range chosen {
			for offset := 0; ; {
				found := strings.Index(data[offset:], word)
				if found < 0 {
					break
				}
				position := offset + found
				offset = position + 1
				covered := slices.ContainsFunc(windows, func(window textWindow) bool {
					return window.start <= max(position+len(word)-span, 0) && window.end >= min(position+span, len(data))
				})
				if !covered {
					t.Fatalf("字面量 %q 在 %d 处的出现未被窗口覆盖: %+v", word, position, windows)
				}
			}
		}
	}
}

// 窗口求值必须与整段求值给出相同的命中结论和版本。正例由模式语法树生成并经
// 上游确认，嵌入含多字节字符的长文本；文本中另放入只含定位字面量的干扰片段，
// 以及第二个正例，验证最左匹配的选择不受窗口划分影响。
func TestWindowedEvaluationMatchesFullEvaluation(t *testing.T) {
	m, err := newHTTPMatcher(upstream.GetRawFingerprints())
	if err != nil {
		t.Fatal(err)
	}
	unique := make(map[string]*httpPattern)
	total := make(map[string]struct{})
	collect := func(groups []patternGroup) {
		for _, g := range groups {
			for _, p := range g.patterns {
				total[p.source] = struct{}{}
				if p.span > 0 {
					unique[p.source] = p
				}
			}
		}
	}
	collect(m.body.groups)
	collect(m.scripts.groups)
	for _, index := range []map[string][]patternGroup{m.headers, m.cookies, m.meta} {
		for _, groups := range index {
			collect(groups)
		}
	}
	sources := make([]string, 0, len(unique))
	for source := range unique {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	step := 1
	if raceEnabled || testing.Short() {
		step = 16
	}
	filler := strings.Repeat("<p>页面 filler 0123</p>\n", 600)
	// fill 返回约 n 字节的填充文本，截断位置对齐到字符起点。
	fill := func(n int) string {
		for n < len(filler) && !utf8.RuneStart(filler[n]) {
			n++
		}
		return filler[:n]
	}
	verified, windowable := 0, 0
	for index := 0; index < len(sources); index += step {
		source := sources[index]
		p := unique[source]
		reference, err := upstream.ParsePattern(source)
		if err != nil {
			continue
		}
		compiled, err := compilePattern(source)
		if err != nil {
			t.Fatalf("上游可解析的模式编译失败: %q: %v", source, err)
		}
		expression, _, _ := strings.Cut(source, `\;`)
		tree, err := syntax.Parse("(?i)"+expression, syntax.Perl)
		if err != nil {
			continue
		}
		windowable++
		decoy := " " + p.literalGroups[p.anchor][0] + " "
		var witnesses []string
		for variant := 0; variant < 4; variant++ {
			witness := strings.ToLower(patternWitness(tree, variant))
			if witness == "" || len(witness) > 1<<12 || !utf8.ValidString(witness) || strings.Contains(witness, "ſ") {
				continue
			}
			if matched, _ := reference.Evaluate(witness); matched && !slices.Contains(witnesses, witness) {
				witnesses = append(witnesses, witness)
			}
		}
		for i, witness := range witnesses {
			texts := []string{
				filler + witness + filler,
				fill(7000) + decoy + fill(5000) + witness + fill(3000) + decoy + filler,
				witness + filler + decoy,
				filler + decoy + witness,
			}
			if other := witnesses[(i+1)%len(witnesses)]; other != witness {
				texts = append(texts, fill(9000)+other+fill(4000)+witness+filler)
			}
			for _, text := range texts {
				if normalizeForFilter(text) != text {
					t.Fatalf("测试文本未归一化: pattern=%q", source)
				}
				wantMatched, wantVersion := reference.Evaluate(text)
				gotMatched, gotVersion := m.evaluate(p, compiled, text, true)
				if gotMatched != wantMatched || gotVersion != wantVersion {
					t.Fatalf("窗口求值与整段求值不一致: pattern=%q span=%d anchor=%q\nwitness=%q\n窗口=(%t,%q) 整段=(%t,%q)",
						source, p.span, p.literalGroups[p.anchor], witness, gotMatched, gotVersion, wantMatched, wantVersion)
				}
				if wantMatched {
					verified++
				}
			}
		}
	}
	t.Logf("可按窗口求值的模式=%d/%d 本次对照模式=%d 正例=%d", len(unique), len(total), windowable, verified)
	if windowable < 200 || step == 1 && verified < 1000 {
		t.Fatalf("覆盖不足: 模式=%d 正例=%d", windowable, verified)
	}
}

func TestMoreSpecificVersion(t *testing.T) {
	for _, tc := range []struct{ current, candidate, want string }{
		{"", "", ""},
		{"", "3", "3"},
		{"3", "", "3"},
		{"3", "3.6.0", "3.6.0"},
		{"3.6.0", "3", "3.6.0"},
		{"3.6.0", "3.7.1", "3.7.1"},
		{"3.7.1", "3.6.0", "3.7.1"},
		{"1.10", "1.9", "1.10"},
		{"2.0", "2.0", "2.0"},
	} {
		if got := moreSpecificVersion(tc.current, tc.candidate); got != tc.want {
			t.Errorf("moreSpecificVersion(%q, %q) = %q，期望 %q", tc.current, tc.candidate, got, tc.want)
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
