package wappalyzer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/phuslu/lru"
	upstream "github.com/projectdiscovery/wappalyzergo"
	"golang.org/x/net/html"
)

type httpPattern struct {
	source     string
	literals   []string
	literalIDs []int
}
type patternGroup struct {
	app      string
	patterns []*httpPattern
}
type appMetadata struct {
	info    upstream.AppInfo
	implies []string
}

// httpMatcher 的规则与索引在发布后只读；编译后的上游正则按工作集缓存。
// 不满足必要字面量的输入不会触发编译，所有候选仍由上游 Evaluate 最终判定。
type httpMatcher struct {
	apps                   map[string]appMetadata
	headers, cookies, meta map[string][]patternGroup
	body, scripts          []patternGroup
	literals               *literalIndex
	programs               *lru.LRUCache[string, *upstream.ParsedPattern]
	compileMu              sync.Mutex
	bits                   sync.Pool
}

func newHTTPMatcher(data string) (*httpMatcher, error) {
	var raw upstream.Fingerprints
	if err := json.NewDecoder(strings.NewReader(data)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("解析技术栈规则失败: %w", err)
	}
	m := &httpMatcher{
		apps:    make(map[string]appMetadata, len(raw.Apps)),
		headers: make(map[string][]patternGroup), cookies: make(map[string][]patternGroup), meta: make(map[string][]patternGroup),
		programs: lru.NewLRUCache[string, *upstream.ParsedPattern](512, lru.WithShards[string, *upstream.ParsedPattern](1)),
	}
	patterns := make(map[string]*httpPattern)
	wordIDs := make(map[string]int)
	var words []string
	pattern := func(source string) *httpPattern {
		if p := patterns[source]; p != nil {
			return p
		}
		p := &httpPattern{source: source, literals: requiredLiterals(source)}
		for _, word := range p.literals {
			id, ok := wordIDs[word]
			if !ok {
				id = len(words)
				wordIDs[word] = id
				words = append(words, word)
			}
			p.literalIDs = append(p.literalIDs, id)
		}
		patterns[source] = p
		return p
	}
	group := func(name string, sources []string) patternGroup {
		g := patternGroup{app: name, patterns: make([]*httpPattern, len(sources))}
		for i, source := range sources {
			g.patterns[i] = pattern(source)
		}
		return g
	}
	names := make([]string, 0, len(raw.Apps))
	for name := range raw.Apps {
		names = append(names, name)
	}
	sort.Strings(names)
	categories := upstream.GetCategoriesMapping()
	for _, name := range names {
		f := raw.Apps[name]
		info := upstream.AppInfo{Description: f.Description, Website: f.Website, CPE: f.CPE, Icon: f.Icon, Categories: make([]string, 0, len(f.Cats))}
		for _, id := range f.Cats {
			if c, ok := categories[id]; ok {
				info.Categories = append(info.Categories, c.Name)
			}
		}
		m.apps[name] = appMetadata{info: info, implies: f.Implies}
		for key, source := range f.Headers {
			m.headers[key] = append(m.headers[key], group(name, []string{source}))
		}
		for key, source := range f.Cookies {
			m.cookies[key] = append(m.cookies[key], group(name, []string{source}))
		}
		for key, sources := range f.Meta {
			m.meta[key] = append(m.meta[key], group(name, sources))
		}
		if len(f.HTML) > 0 {
			m.body = append(m.body, group(name, f.HTML))
		}
		if len(f.ScriptSrc) > 0 {
			m.scripts = append(m.scripts, group(name, f.ScriptSrc))
		}
	}
	m.literals = newLiteralIndex(words)
	bitWords := (len(words) + 63) / 64
	m.bits.New = func() any { b := make([]uint64, bitWords); return &b }
	return m, nil
}

func (m *httpMatcher) program(source string) *upstream.ParsedPattern {
	if p, ok := m.programs.Get(source); ok {
		return p
	}
	m.compileMu.Lock()
	defer m.compileMu.Unlock()
	if p, ok := m.programs.Get(source); ok {
		return p
	}
	p, err := upstream.ParsePattern(source)
	if err != nil {
		// 与上游一致，无法解析的模式不参与匹配；同时缓存失败避免重复编译。
		m.programs.Set(source, nil)
		return nil
	}
	m.programs.Set(source, p)
	return p
}

func (m *httpMatcher) matchGroup(g patternGroup, data string, bits []uint64, first bool) (bool, string, int) {
	matched, version, confidence := false, "", 100
	filterData := data
	if bits == nil {
		filterData = normalizeForFilter(data)
	}
	for _, p := range g.patterns {
		if len(p.literalIDs) > 0 {
			present := false
			for i, id := range p.literalIDs {
				if bits != nil {
					present = bits[id/64]&(uint64(1)<<uint(id%64)) != 0
				} else {
					present = strings.Contains(filterData, p.literals[i])
				}
				if present {
					break
				}
			}
			if !present {
				continue
			}
		}
		compiled := m.program(p.source)
		if compiled == nil {
			continue
		}
		if ok, v := compiled.Evaluate(data); ok {
			matched, confidence = true, compiled.Confidence
			if version == "" {
				version = v
			}
			if first {
				break
			}
		}
	}
	return matched, version, confidence
}

func (m *httpMatcher) record(found upstream.UniqueFingerprints, name, version string, confidence int) {
	found.SetIfNotExists(name, version, confidence)
	for _, implied := range m.apps[name].implies {
		found.SetIfNotExists(implied, "", confidence)
	}
}

func (m *httpMatcher) matchFields(found upstream.UniqueFingerprints, values map[string]string, index map[string][]patternGroup) {
	seen := make(map[string]struct{})
	for key, value := range values {
		for _, g := range index[key] {
			if _, ok := seen[g.app]; ok {
				continue
			}
			if ok, version, confidence := m.matchGroup(g, value, nil, true); ok {
				seen[g.app] = struct{}{}
				m.record(found, g.app, version, confidence)
			}
		}
	}
}

func (m *httpMatcher) matchText(found upstream.UniqueFingerprints, groups []patternGroup, data string, bits []uint64) {
	m.literals.match(normalizeForFilter(data), bits)
	for _, g := range groups {
		if ok, version, confidence := m.matchGroup(g, data, bits, false); ok {
			m.record(found, g.app, version, confidence)
		}
	}
}

// 必要字面量限定为 ASCII。长 s 与 ASCII s 属于同一 SimpleFold 等价类，
// ToLower 却不将其折叠为 s；只在预筛选副本上归一化，正则输入保持原样。
func normalizeForFilter(data string) string {
	data = strings.ToLower(data)
	return strings.ReplaceAll(data, "ſ", "s")
}

func (m *httpMatcher) FingerprintWithInfo(headers map[string][]string, body []byte) map[string]upstream.AppInfo {
	found := upstream.NewUniqueFingerprints()
	normalized := make(map[string]string, len(headers))
	for key, values := range headers {
		normalized[strings.ToLower(key)] = strings.ToLower(strings.Join(values, ", "))
	}
	m.matchFields(found, normalized, m.headers)
	if value, ok := normalized["set-cookie"]; ok {
		cookies := make(map[string]string)
		for _, v := range strings.Split(value, " ") {
			var parts []string
			switch {
			case strings.Contains(v, ","):
				parts = strings.Split(v, ",")
			case strings.Contains(v, ";"):
				parts = strings.Split(v, ";")
			default:
				parts = []string{v}
			}
			for _, part := range parts {
				if k, val, ok := strings.Cut(strings.Trim(part, " "), "="); ok {
					cookies[k] = val
				}
			}
		}
		m.matchFields(found, cookies, m.cookies)
	}
	data := strings.ToLower(string(body))
	bitBuffer := m.bits.Get().(*[]uint64)
	defer m.bits.Put(bitBuffer)
	m.matchText(found, m.body, data, *bitBuffer)
	tokenizer := html.NewTokenizer(strings.NewReader(data))
	for {
		kind := tokenizer.Next()
		if kind == html.ErrorToken {
			break
		}
		if kind != html.StartTagToken && kind != html.SelfClosingTagToken {
			continue
		}
		token := tokenizer.Token()
		switch token.Data {
		case "script":
			if kind != html.StartTagToken {
				continue
			}
			if len(token.Attr) == 0 {
				tokenizer.Next()
				continue
			}
			var source string
			for _, attr := range token.Attr {
				if attr.Key == "src" {
					source = attr.Val
				}
			}
			m.matchText(found, m.scripts, source, *bitBuffer)
		case "meta":
			if len(token.Attr) < 2 {
				continue
			}
			var name, content string
			for _, attr := range token.Attr {
				switch attr.Key {
				case "name":
					name = attr.Val
				case "content":
					content = attr.Val
				}
			}
			for _, g := range m.meta[name] {
				if ok, version, confidence := m.matchGroup(g, content, nil, true); ok {
					m.record(found, g.app, version, confidence)
				}
			}
		}
	}
	apps := found.GetValues()
	result := make(map[string]upstream.AppInfo, len(apps))
	for name := range apps {
		if app, ok := m.apps[name]; ok {
			result[name] = app.info
		}
		if strings.Contains(name, ":") {
			if parts := strings.Split(name, ":"); len(parts) == 2 {
				if app, ok := m.apps[parts[0]]; ok {
					result[name] = app.info
				}
			}
		}
	}
	return result
}
