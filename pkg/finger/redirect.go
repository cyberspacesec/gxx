package finger

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

// 客户端跳转（meta refresh 与脚本跳转）的静态识别。
//
// 这里不执行脚本，只识别写法明确、目标唯一的跳转；识别不了就当作没有跳转。
// 调用方只会跟随与页面同一资产的目标，因此识别错误最多导致多请求一次本资产的
// 其他页面，不会访问到别的资产。

// 跳转类型，写入扫描结果。
const (
	RedirectHTTP       = "http"
	RedirectRefresh    = "refresh"
	RedirectJavaScript = "javascript"
)

const (
	// 超过该延迟的 refresh 多为会话超时或定时刷新，不是入口跳转。
	maxRefreshDelay = 10
	// 跳转壳的正文上限。真实页面即使内容很少，内联框架代码也会超过这个大小。
	maxShellBytes = 16 << 10
	// 跳转壳的可见文字上限（如"正在跳转，请稍候"）。
	maxShellText = 512
)

// ClientRedirect 返回页面声明的客户端跳转目标与类型；没有可识别的跳转时目标为 nil。
//
// 依次检查 Refresh 响应头、<meta http-equiv="refresh"> 和跳转壳中的脚本。
// 返回的目标已按页面地址及 <base href> 解析为绝对地址，只可能是 http/https，
// 并且与页面地址不同（忽略片段）。
func ClientRedirect(page *url.URL, header http.Header, body []byte) (*url.URL, string) {
	if page == nil {
		return nil, ""
	}
	if raw, ok := parseRefresh(header.Get("Refresh")); ok {
		if target := resolveRedirect(page, page, raw); target != nil {
			return target, RedirectRefresh
		}
	}
	if len(body) == 0 {
		return nil, ""
	}
	// 绝大多数页面两种跳转都没有，先用字节查找排除，避免无谓的词法扫描。
	mayRefresh := containsFold(body, "http-equiv")
	mayScript := len(body) <= maxShellBytes && bytes.Contains(body, []byte("location"))
	if !mayRefresh && !mayScript {
		return nil, ""
	}

	base := page
	baseSeen := false
	refresh := ""
	shell := mayScript
	visible := 0
	var scripts []string
	depthNoscript, depthTemplate := 0, 0
	lexer := metadataLexer[[]byte]{body: body}
	inScript := false
	for {
		tok, ok := lexer.next()
		if !ok {
			break
		}
		if len(tok.name) == 0 {
			if tok.raw {
				if inScript && shell && depthNoscript == 0 && depthTemplate == 0 {
					scripts = append(scripts, string(tok.text))
				}
				inScript = false
				continue
			}
			if depthNoscript == 0 && depthTemplate == 0 {
				visible += len(bytes.TrimSpace(tok.text))
			}
			continue
		}
		inScript = false
		switch {
		case metadataEqualFold(tok.name, "noscript"):
			depthNoscript = nest(depthNoscript, tok.end)
		case metadataEqualFold(tok.name, "template"):
			depthTemplate = nest(depthTemplate, tok.end)
		}
		if tok.end || depthNoscript > 0 || depthTemplate > 0 {
			continue
		}
		switch {
		case metadataEqualFold(tok.name, "base"):
			if href := metadataAttribute(tok.attrs, "href"); href != "" && !baseSeen {
				baseSeen = true
				if u, err := url.Parse(strings.TrimSpace(href)); err == nil {
					if resolved := page.ResolveReference(u); resolved.Scheme == "http" || resolved.Scheme == "https" {
						base = resolved
					}
				}
			}
		case metadataEqualFold(tok.name, "meta"):
			if refresh == "" && strings.EqualFold(strings.TrimSpace(metadataAttribute(tok.attrs, "http-equiv")), "refresh") {
				if raw, ok := parseRefresh(metadataAttribute(tok.attrs, "content")); ok {
					refresh = raw
				}
			}
		case metadataEqualFold(tok.name, "script"):
			// 外链脚本与非脚本类型（模板、JSON）不参与识别。
			kind := strings.ToLower(strings.TrimSpace(metadataAttribute(tok.attrs, "type")))
			inScript = metadataAttribute(tok.attrs, "src") == "" && (kind == "" || kind == "module" || strings.Contains(kind, "javascript") || strings.Contains(kind, "ecmascript"))
		case metadataEqualFold(tok.name, "body"):
			if onload := metadataAttribute(tok.attrs, "onload"); onload != "" && shell {
				scripts = append(scripts, onload)
			}
		case metadataEqualFold(tok.name, "form"), metadataEqualFold(tok.name, "input"), metadataEqualFold(tok.name, "textarea"),
			metadataEqualFold(tok.name, "select"), metadataEqualFold(tok.name, "button"), metadataEqualFold(tok.name, "iframe"),
			metadataEqualFold(tok.name, "frame"), metadataEqualFold(tok.name, "frameset"):
			// 有表单、输入控件或框架的是真实页面，其中的跳转语句多半有条件。
			shell = false
		}
	}
	if refresh != "" {
		if target := resolveRedirect(page, base, refresh); target != nil {
			return target, RedirectRefresh
		}
	}
	if !shell || visible > maxShellText {
		return nil, ""
	}
	// 整个页面只出现一个不同的跳转目标时才采用；按设备、语言分流等多目标写法无法静态判断。
	var found *url.URL
	for _, script := range scripts {
		for _, raw := range scriptRedirects(script) {
			target := resolveRedirect(page, base, raw)
			if target == nil {
				continue
			}
			if found != nil && found.String() != target.String() {
				return nil, ""
			}
			found = target
		}
	}
	if found == nil {
		return nil, ""
	}
	return found, RedirectJavaScript
}

func nest(depth int, end bool) int {
	if !end {
		return depth + 1
	}
	return max(depth-1, 0)
}

func containsFold(body []byte, lower string) bool {
	for at := 0; ; {
		i := bytes.IndexByte(body[at:], lower[0])
		j := bytes.IndexByte(body[at:], lower[0]-'a'+'A')
		if i < 0 || j >= 0 && j < i {
			i = j
		}
		if i < 0 || at+i+len(lower) > len(body) {
			return false
		}
		at += i
		if metadataEqualFold(body[at:at+len(lower)], lower) {
			return true
		}
		at++
	}
}

// parseRefresh 解析 refresh 的 "延迟; url=地址"，返回地址。
// 没有地址（定时刷新自身）或延迟超过 maxRefreshDelay 时返回 false。
func parseRefresh(content string) (string, bool) {
	content = strings.TrimSpace(content)
	at := 0
	for at < len(content) && content[at] >= '0' && content[at] <= '9' {
		at++
	}
	if at == 0 || at > 3 {
		return "", false
	}
	delay := 0
	for _, c := range content[:at] {
		delay = delay*10 + int(c-'0')
	}
	// 小数部分不影响是否跟随。
	for at < len(content) && (content[at] == '.' || content[at] >= '0' && content[at] <= '9') {
		at++
	}
	rest := strings.TrimLeft(content[at:], " \t\r\n")
	if delay > maxRefreshDelay || rest == "" || rest[0] != ';' && rest[0] != ',' {
		return "", false
	}
	rest = strings.TrimLeft(rest[1:], " \t\r\n")
	if len(rest) >= 3 && strings.EqualFold(rest[:3], "url") {
		if value := strings.TrimLeft(rest[3:], " \t\r\n"); strings.HasPrefix(value, "=") {
			rest = strings.TrimLeft(value[1:], " \t\r\n")
		}
	}
	if rest != "" && (rest[0] == '\'' || rest[0] == '"') {
		if end := strings.IndexByte(rest[1:], rest[0]); end >= 0 {
			rest = rest[1 : 1+end]
		} else {
			rest = rest[1:]
		}
	}
	rest = strings.TrimSpace(rest)
	return rest, rest != ""
}

// resolveRedirect 把跳转地址解析为绝对地址。非 http/https、无法解析或
// 与当前页面相同（忽略片段）的地址返回 nil。
func resolveRedirect(page, base *url.URL, raw string) *url.URL {
	raw = iconURLControlStripper.Replace(strings.TrimSpace(raw))
	if raw == "" {
		return nil
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	target := base.ResolveReference(ref)
	if target.Host == "" || target.Scheme != "http" && target.Scheme != "https" {
		return nil
	}
	target.Fragment, target.RawFragment = "", ""
	current := *page
	current.Fragment, current.RawFragment = "", ""
	if current.Path == "" {
		current.Path = "/"
	}
	if target.Path == "" {
		target.Path = "/"
	}
	if target.String() == current.String() {
		return nil
	}
	return target
}

// scriptRedirects 返回脚本中跳转语句的字面量目标。
//
// 识别的写法：location / location.href 赋值，以及 location.replace()、
// location.assign() 调用；location 可以挂在 window、self、top、parent、document、
// globalThis 上。目标必须是字符串字面量；字面量之后用 + 拼接时，只有字面量已含
// 查询串（路径完整，拼接的是时间戳一类参数值）才采用。
func scriptRedirects(source string) []string {
	var targets []string
	s := scriptScanner{src: source}
	var chain []string // 当前以 . 连接的标识符链
	previous := scriptToken{}
	for {
		tok := s.next()
		if tok.kind == scriptEOF {
			return targets
		}
		if tok.kind != scriptIdent {
			chain = chain[:0]
			previous = tok
			continue
		}
		// 收集 a.b.c 形式的标识符链；前面紧跟 . 的不是链的起点（如 x().location）。
		if previous.kind == scriptPunct && previous.text == "." {
			previous = tok
			continue
		}
		declared := previous.kind == scriptIdent && (previous.text == "var" || previous.text == "let" || previous.text == "const")
		chain = append(chain[:0], tok.text)
		for {
			mark := s.mark()
			if dot := s.next(); dot.kind != scriptPunct || dot.text != "." {
				s.reset(mark)
				break
			}
			name := s.next()
			if name.kind != scriptIdent {
				s.reset(mark)
				break
			}
			chain = append(chain, name.text)
		}
		previous = scriptToken{kind: scriptIdent, text: chain[len(chain)-1]}
		call, ok := locationChain(chain)
		if !ok || declared {
			continue
		}
		mark := s.mark()
		next := s.next()
		switch {
		case !call && next.kind == scriptPunct && next.text == "=":
			if peek := s.next(); peek.kind == scriptString {
				if target, ok := literalTarget(&s, peek); ok {
					targets = append(targets, target)
				}
				continue
			}
		case call && next.kind == scriptPunct && next.text == "(":
			if peek := s.next(); peek.kind == scriptString {
				if target, ok := literalTarget(&s, peek); ok {
					targets = append(targets, target)
				}
				continue
			}
		}
		s.reset(mark)
	}
}

// locationChain 判断标识符链是否指向页面地址；call 表示链以 replace / assign 结尾。
func locationChain(chain []string) (call, ok bool) {
	n := len(chain)
	if n > 0 && (chain[n-1] == "replace" || chain[n-1] == "assign") {
		call, n = true, n-1
	} else if n > 0 && chain[n-1] == "href" {
		n--
	}
	if n == 0 || chain[n-1] != "location" {
		return false, false
	}
	for _, name := range chain[:n-1] {
		switch name {
		case "window", "self", "top", "parent", "document", "globalThis":
		default:
			return false, false
		}
	}
	return call, true
}

// literalTarget 检查字面量之后的记号，决定它能否作为跳转目标。
func literalTarget(s *scriptScanner, literal scriptToken) (string, bool) {
	if literal.dynamic {
		return "", false
	}
	mark := s.mark()
	next := s.next()
	s.reset(mark)
	if next.kind == scriptPunct {
		switch next.text {
		case "+":
			// 路径必须完整：只接受拼接发生在查询串里的写法。
			return literal.text, strings.Contains(literal.text, "?")
		case ".", "[", "(", "?", "=", "&", "|", "*", "/", "-", "%", "<", ">", "!":
			return "", false
		}
	}
	return literal.text, true
}

const (
	scriptEOF = iota
	scriptIdent
	scriptString
	scriptPunct
)

type scriptToken struct {
	kind    int
	text    string
	dynamic bool // 模板字符串含 ${} 插值
}

// scriptScanner 是只为识别跳转语句服务的最小 JavaScript 词法扫描器：
// 区分标识符、字符串、注释、正则字面量与标点，使字符串和注释里的"代码"不会被误认。
type scriptScanner struct {
	src  string
	pos  int
	last scriptToken
}

type scriptMark struct {
	pos  int
	last scriptToken
}

func (s *scriptScanner) mark() scriptMark      { return scriptMark{s.pos, s.last} }
func (s *scriptScanner) reset(mark scriptMark) { s.pos, s.last = mark.pos, mark.last }

func (s *scriptScanner) next() scriptToken {
	tok := s.scan()
	s.last = tok
	return tok
}

func (s *scriptScanner) scan() scriptToken {
	for s.pos < len(s.src) {
		c := s.src[s.pos]
		rest := s.src[s.pos:]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			s.pos++
		case strings.HasPrefix(rest, "//"), strings.HasPrefix(rest, "<!--"), strings.HasPrefix(rest, "-->"):
			// HTML 注释标记在脚本中等同于单行注释。
			end := strings.IndexAny(rest, "\r\n")
			if end < 0 {
				end = len(rest)
			}
			s.pos += end
		case strings.HasPrefix(rest, "/*"):
			end := strings.Index(rest[2:], "*/")
			if end < 0 {
				s.pos = len(s.src)
			} else {
				s.pos += end + 4
			}
		case c == '"' || c == '\'' || c == '`':
			return s.scanString(c)
		case c == '/' && s.regexAllowed():
			s.skipRegex()
			return scriptToken{kind: scriptPunct, text: "regex"}
		case c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= utf8.RuneSelf:
			start := s.pos
			for s.pos < len(s.src) {
				c = s.src[s.pos]
				if c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= utf8.RuneSelf {
					s.pos++
					continue
				}
				break
			}
			return scriptToken{kind: scriptIdent, text: s.src[start:s.pos]}
		case c == '=' && s.pos+1 < len(s.src) && (s.src[s.pos+1] == '=' || s.src[s.pos+1] == '>'):
			// == / === / => 不是赋值。
			s.pos += 2
			if s.pos < len(s.src) && s.src[s.pos] == '=' {
				s.pos++
			}
			return scriptToken{kind: scriptPunct, text: "=="}
		case (c == '!' || c == '<' || c == '>' || c == '+' || c == '-' || c == '*' || c == '%' || c == '&' || c == '|' || c == '^') && s.pos+1 < len(s.src) && s.src[s.pos+1] == '=':
			// 复合赋值与比较（+=、!=、<= 等）不是对地址的直接赋值。
			s.pos += 2
			return scriptToken{kind: scriptPunct, text: "op="}
		default:
			s.pos++
			return scriptToken{kind: scriptPunct, text: string(c)}
		}
	}
	return scriptToken{kind: scriptEOF}
}

// regexAllowed 判断当前位置的 / 是正则字面量的开头还是除号：
// 前一个记号是值（标识符、字符串、右括号）时为除号。
func (s *scriptScanner) regexAllowed() bool {
	switch s.last.kind {
	case scriptIdent:
		return s.last.text == "return" || s.last.text == "typeof" || s.last.text == "case"
	case scriptString:
		return false
	case scriptPunct:
		return s.last.text != ")" && s.last.text != "]" && s.last.text != "}"
	}
	return true
}

func (s *scriptScanner) skipRegex() {
	inClass := false
	for s.pos++; s.pos < len(s.src); s.pos++ {
		switch c := s.src[s.pos]; {
		case c == '\\':
			s.pos++
		case c == '\n' || c == '\r':
			return
		case c == '[':
			inClass = true
		case c == ']':
			inClass = false
		case c == '/' && !inClass:
			s.pos++
			return
		}
	}
}

func (s *scriptScanner) scanString(quote byte) scriptToken {
	var b strings.Builder
	tok := scriptToken{kind: scriptString}
	for s.pos++; s.pos < len(s.src); s.pos++ {
		c := s.src[s.pos]
		switch {
		case c == quote:
			s.pos++
			tok.text = b.String()
			return tok
		case c == '\\' && s.pos+1 < len(s.src):
			s.pos++
			switch e := s.src[s.pos]; e {
			case 'n', 'r', 't', '\n':
				// 地址中不会出现空白转义，丢弃即可。
			case 'x':
				if v, ok := hexValue(s.src, s.pos+1, 2); ok {
					b.WriteRune(v)
					s.pos += 2
				}
			case 'u':
				if v, ok := hexValue(s.src, s.pos+1, 4); ok {
					b.WriteRune(v)
					s.pos += 4
				}
			default:
				b.WriteByte(e)
			}
		case (c == '\n' || c == '\r') && quote != '`':
			// 未闭合的字符串：不是有效脚本，放弃这个记号。
			tok.dynamic = true
			tok.text = b.String()
			return tok
		case c == '$' && quote == '`' && s.pos+1 < len(s.src) && s.src[s.pos+1] == '{':
			tok.dynamic = true
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	tok.dynamic = true
	tok.text = b.String()
	return tok
}

func hexValue(src string, at, n int) (rune, bool) {
	if at+n > len(src) {
		return 0, false
	}
	var v rune
	for _, c := range src[at : at+n] {
		switch {
		case c >= '0' && c <= '9':
			v = v<<4 | (c - '0')
		case c >= 'a' && c <= 'f':
			v = v<<4 | (c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			v = v<<4 | (c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return v, true
}
