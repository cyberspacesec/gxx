package wappalyzer

import (
	"encoding/json"
	"fmt"
	"math/bits"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/cyberspacesec/gxx/internal/casefold"
	"github.com/phuslu/lru"
	upstream "github.com/projectdiscovery/wappalyzergo"
	"golang.org/x/net/html"
)

// httpPattern 的每个 literalGroups 元素都是必要条件：匹配必须同时满足所有组，
// 每组至少出现其中一个字面量。literalIDs 与 literalGroups 一一对应。
//
// span 非零时模式可按窗口求值：任何匹配都完整包含 anchor 组的某个字面量，
// 且长度不超过 span 字节，因此只需检查这些字面量出现位置附近的文本。
type httpPattern struct {
	source        string
	literalGroups [][]string
	literalIDs    [][]int
	anchor        int
	span          int
}

// mayMatch 判断预筛选能否排除该模式：所有组都满足时才可能匹配，任一组的字面量全部缺失
// 即可证明正则不会匹配。present 非空时查 Aho-Corasick 结果位图，否则在 filterData 中逐个查找。
func (p *httpPattern) mayMatch(present []uint64, filterData string) bool {
	for group, ids := range p.literalIDs {
		found := false
		for i, id := range ids {
			if present != nil {
				found = present[id/64]&(uint64(1)<<uint(id%64)) != 0
			} else {
				found = strings.Contains(filterData, p.literalGroups[group][i])
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// triggeredBy 报告 id 是否为 anchor 组中编号最小的已出现字面量。
// 同组多个字面量同时出现时，模式只经由其中一个触发，避免重复求值。
func (p *httpPattern) triggeredBy(id int, present []uint64) bool {
	for _, other := range p.literalIDs[p.anchor] {
		if other < id && present[other/64]&(uint64(1)<<uint(other%64)) != 0 {
			return false
		}
	}
	return true
}

type patternGroup struct {
	app      string
	patterns []*httpPattern
}

type appMetadata struct {
	info    upstream.AppInfo
	implies []string
}

type patternRef struct{ group, pattern int32 }

// textIndex 按必要字面量倒排一类文本（正文或脚本地址）的全部模式。
// 一次 Aho-Corasick 扫描得到出现的字面量后，只访问由它们触发的模式，
// 不再逐应用遍历；没有必要字面量的模式保留在 always 中逐段求值。
type textIndex struct {
	groups   []patternGroup
	always   []patternRef
	triggers [][]patternRef
}

func newTextIndex(groups []patternGroup, words int) *textIndex {
	idx := &textIndex{groups: groups, triggers: make([][]patternRef, words)}
	for g, group := range groups {
		for p, pattern := range group.patterns {
			ref := patternRef{int32(g), int32(p)}
			if len(pattern.literalIDs) == 0 {
				idx.always = append(idx.always, ref)
				continue
			}
			for _, id := range pattern.literalIDs[pattern.anchor] {
				idx.triggers[id] = append(idx.triggers[id], ref)
			}
		}
	}
	return idx
}

// groupMatch 归并同一应用在一段文本上的全部命中模式。
type groupMatch struct {
	group      int32
	confidence int
	version    string
}

// httpMatcher 的规则与索引在发布后只读；编译后的上游正则按工作集缓存。
// 不满足必要字面量的输入不会触发编译，所有候选仍由上游 Evaluate 最终判定。
type httpMatcher struct {
	apps                   map[string]appMetadata
	headers, cookies, meta map[string][]patternGroup
	body, scripts          *textIndex
	literals               *literalIndex
	programs               *lru.LRUCache[string, *compiledPattern]
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
		programs: lru.NewLRUCache[string, *compiledPattern](512, lru.WithShards[string, *compiledPattern](1)),
	}
	patterns := make(map[string]*httpPattern)
	wordIDs := make(map[string]int)
	var words []string
	pattern := func(source string) *httpPattern {
		if p := patterns[source]; p != nil {
			return p
		}
		p := &httpPattern{source: source, literalGroups: requiredLiteralGroups(source)}
		shortest := 0
		for index, group := range p.literalGroups {
			ids := make([]int, len(group))
			length := len(group[0])
			for i, word := range group {
				id, ok := wordIDs[word]
				if !ok {
					id = len(words)
					wordIDs[word] = id
					words = append(words, word)
				}
				ids[i] = id
				length = min(length, len(word))
			}
			p.literalIDs = append(p.literalIDs, ids)
			// 以最短字面量最长的组定位窗口：字面量越长，出现位置越少。
			if length > shortest {
				p.anchor, shortest = index, length
			}
		}
		if len(p.literalGroups) > 0 {
			p.span = matchSpan(source)
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
	var body, scripts []patternGroup
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
			body = append(body, group(name, f.HTML))
		}
		if len(f.ScriptSrc) > 0 {
			scripts = append(scripts, group(name, f.ScriptSrc))
		}
	}
	m.literals = newLiteralIndex(words)
	m.body, m.scripts = newTextIndex(body, len(words)), newTextIndex(scripts, len(words))
	bitWords := (len(words) + 63) / 64
	m.bits.New = func() any { b := make([]uint64, bitWords); return &b }
	return m, nil
}

func (m *httpMatcher) program(source string) *compiledPattern {
	if p, ok := m.programs.Get(source); ok {
		return p
	}
	m.compileMu.Lock()
	defer m.compileMu.Unlock()
	if p, ok := m.programs.Get(source); ok {
		return p
	}
	p, err := compilePattern(source)
	if err != nil {
		// 与上游一致，无法解析的模式不参与匹配；同时缓存失败避免重复编译。
		m.programs.Set(source, nil)
		return nil
	}
	m.programs.Set(source, p)
	return p
}

const (
	// 文本短于该长度时整段求值更便宜，不值得定位窗口。
	minWindowText = 8 << 10
	// 单个模式最多检查的窗口数；字面量过于常见时退回整段求值。
	maxWindows = 32
)

type textWindow struct{ start, end int }

// literalWindows 返回 words 在 data 中每次出现所对应的求值窗口，按起点升序且互不相交。
//
// 完整包含某次出现、长度不超过 span 的匹配必然落在该次出现前后各 span 字节之内。
// 窗口边界对齐到字符起点，使截取后的解码结果与整段文本一致。窗口过多或合计
// 长度接近全文时返回 false，由调用方整段求值。
func literalWindows(windows []textWindow, data string, words []string, span int) ([]textWindow, bool) {
	total := 0
	for _, word := range words {
		last := -1
		for offset := 0; offset < len(data); {
			index := strings.Index(data[offset:], word)
			if index < 0 {
				break
			}
			position := offset + index
			offset = position + 1
			start, end := max(position+len(word)-span, 0), min(position+span, len(data))
			for start > 0 && !utf8.RuneStart(data[start]) {
				start--
			}
			for end < len(data) && !utf8.RuneStart(data[end]) {
				end++
			}
			// 同一字面量的出现按位置递增，相邻窗口可就地合并。
			if last >= 0 && start <= windows[last].end {
				total += end - windows[last].end
				windows[last].end = end
				continue
			}
			if len(windows) == maxWindows {
				return nil, false
			}
			windows = append(windows, textWindow{start, end})
			last = len(windows) - 1
			total += end - start
		}
		if total > len(data)/2 {
			return nil, false
		}
	}
	if len(words) > 1 && len(windows) > 1 {
		slices.SortFunc(windows, func(a, b textWindow) int { return a.start - b.start })
		merged := windows[:1]
		for _, window := range windows[1:] {
			if tail := &merged[len(merged)-1]; window.start <= tail.end {
				tail.end = max(tail.end, window.end)
			} else {
				merged = append(merged, window)
			}
		}
		windows = merged
	}
	return windows, true
}

// evaluate 返回上游对 data 的判定。windowed 表示 data 与预筛选使用的归一化文本
// 完全相同，此时字面量在 data 中的位置可用于截取窗口；窗口按起点升序检查，
// 首个命中即为整段文本的最左匹配，版本提取结果与整段求值一致。
func (m *httpMatcher) evaluate(p *httpPattern, compiled *compiledPattern, data string, windowed bool) (bool, string) {
	if !windowed || p.span == 0 {
		return compiled.evaluate(data)
	}
	var buffer [maxWindows]textWindow
	windows, ok := literalWindows(buffer[:0], data, p.literalGroups[p.anchor], p.span)
	if !ok {
		return compiled.evaluate(data)
	}
	for _, window := range windows {
		if matched, version := compiled.evaluate(data[window.start:window.end]); matched {
			return true, version
		}
	}
	return false, ""
}

// matchGroup 按上游语义归并同一应用的全部模式：命中任一模式即成立，
// 置信度取命中模式中的最大值，版本取最具体者。全部模式都会求值，不提前结束。
func (m *httpMatcher) matchGroup(g patternGroup, data string) (bool, string, int) {
	matched, version, confidence := false, "", 0
	filterData := normalizeForFilter(data)
	for _, p := range g.patterns {
		if !p.mayMatch(nil, filterData) {
			continue
		}
		compiled := m.program(p.source)
		if compiled == nil {
			continue
		}
		if ok, v := compiled.evaluate(data); ok {
			matched = true
			confidence = max(confidence, compiled.confidence)
			version = moreSpecificVersion(version, v)
		}
	}
	return matched, version, confidence
}

// moreSpecificVersion 与上游 isMoreSpecific 一致：段数更多的版本更具体，
// 段数相同时取数值更大者；空版本不覆盖已有版本。
func moreSpecificVersion(current, candidate string) string {
	if candidate == "" {
		return current
	}
	if current == "" {
		return candidate
	}
	a, b := versionParts(candidate), versionParts(current)
	if len(a) != len(b) {
		if len(a) > len(b) {
			return candidate
		}
		return current
	}
	for i := range a {
		if a[i] != b[i] {
			if a[i] > b[i] {
				return candidate
			}
			return current
		}
	}
	return current
}

// versionParts 按 '.' 切分并解析各段；空段被忽略，非数字段记为 0。
func versionParts(version string) []int {
	fields := strings.FieldsFunc(version, func(r rune) bool { return r == '.' })
	parts := make([]int, len(fields))
	for i, field := range fields {
		if n, err := strconv.Atoi(field); err == nil {
			parts[i] = n
		}
	}
	return parts
}

func (m *httpMatcher) record(found upstream.UniqueFingerprints, name, version string, confidence int) {
	found.SetIfNotExists(name, version, confidence)
	for _, implied := range m.apps[name].implies {
		found.SetIfNotExists(implied, "", confidence)
	}
}

// matchFields 匹配响应头或 Cookie。同一应用可能在多个字段上声明模式，
// 上游按应用归并后只记录一次，这里保持相同的归并方式。
func (m *httpMatcher) matchFields(found upstream.UniqueFingerprints, values map[string]string, index map[string][]patternGroup) {
	type fieldMatch struct {
		version    string
		confidence int
	}
	var matches map[string]fieldMatch
	for key, value := range values {
		for _, g := range index[key] {
			ok, version, confidence := m.matchGroup(g, value)
			if !ok {
				continue
			}
			if matches == nil {
				matches = make(map[string]fieldMatch)
			}
			current := matches[g.app]
			current.confidence = max(current.confidence, confidence)
			current.version = moreSpecificVersion(current.version, version)
			matches[g.app] = current
		}
	}
	for app, match := range matches {
		m.record(found, app, match.version, match.confidence)
	}
}

// matchText 匹配正文或脚本地址。data 必须是送入正则的文本，filter 是其归一化副本。
func (m *httpMatcher) matchText(found upstream.UniqueFingerprints, idx *textIndex, data, filter string, present []uint64) {
	m.literals.match(filter, present)
	// 归一化未改动文本时，字面量在 data 中的位置与预筛选一致，可以按窗口求值。
	windowed := len(data) >= minWindowText && filter == data
	var buffer [8]groupMatch
	matches := buffer[:0]
	for _, ref := range idx.always {
		matches = m.evaluateRef(matches, idx, ref, data, windowed)
	}
	for word, set := range present {
		for ; set != 0; set &= set - 1 {
			id := word*64 + bits.TrailingZeros64(set)
			for _, ref := range idx.triggers[id] {
				p := idx.groups[ref.group].patterns[ref.pattern]
				if p.triggeredBy(id, present) && p.mayMatch(present, "") {
					matches = m.evaluateRef(matches, idx, ref, data, windowed)
				}
			}
		}
	}
	for _, match := range matches {
		m.record(found, idx.groups[match.group].app, match.version, match.confidence)
	}
}

func (m *httpMatcher) evaluateRef(matches []groupMatch, idx *textIndex, ref patternRef, data string, windowed bool) []groupMatch {
	p := idx.groups[ref.group].patterns[ref.pattern]
	compiled := m.program(p.source)
	if compiled == nil {
		return matches
	}
	ok, version := m.evaluate(p, compiled, data, windowed)
	if !ok {
		return matches
	}
	for i := range matches {
		if matches[i].group == ref.group {
			matches[i].confidence = max(matches[i].confidence, compiled.confidence)
			matches[i].version = moreSpecificVersion(matches[i].version, version)
			return matches
		}
	}
	return append(matches, groupMatch{group: ref.group, confidence: compiled.confidence, version: version})
}

// 必要字面量限定为 ASCII。长 s 与 ASCII s 属于同一 SimpleFold 等价类，
// ToLower 却不将其折叠为 s；只在预筛选副本上归一化，正则输入保持原样。
func normalizeForFilter(data string) string {
	return foldLongS(strings.ToLower(data))
}

// foldLongS 处理已小写化的文本：其中只剩长 s 需要折叠。
func foldLongS(lowered string) string {
	return strings.ReplaceAll(lowered, "ſ", "s")
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
	// 正文在调用期间只读；小写副本与 bytes.ToLower 逐字节一致，无改动时直接复用原数组。
	data := casefold.LowerString(body)
	bitBuffer := m.bits.Get().(*[]uint64)
	defer m.bits.Put(bitBuffer)
	m.matchText(found, m.body, data, foldLongS(data), *bitBuffer)
	// 同一地址的脚本只需匹配一次：重复记录只会累加置信度，不改变识别结果。
	var scripts map[string]struct{}
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
			if _, seen := scripts[source]; seen {
				continue
			}
			if scripts == nil {
				scripts = make(map[string]struct{})
			}
			scripts[source] = struct{}{}
			m.matchText(found, m.scripts, source, normalizeForFilter(source), *bitBuffer)
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
				if ok, version, confidence := m.matchGroup(g, content); ok {
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
