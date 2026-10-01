package finger

import (
	"bytes"
	"github.com/cyberspacesec/gxx/v2/utils/common"
	"html"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ExtractICPRecordFromBody 从只读正文提取备案号，不保留整页引用。
func ExtractICPRecordFromBody(body []byte) string {
	if !metadataMayContainICP(body) {
		return ""
	}
	if !utf8.Valid(body) {
		return extractICPText(common.Str2UTF8(string(body)))
	}
	return extractICPText(body)
}

// ExtractICPRecord 支持 HTML 与纯文本；优先采用备案官网链接中的有效号码。
func ExtractICPRecord(body string) string {
	if !metadataMayContainICP(body) {
		return ""
	}
	if !utf8.ValidString(body) {
		return extractICPText(common.Str2UTF8(body))
	}
	return extractICPText(body)
}

func metadataMayContainICP[S metadataSource](body S) bool {
	// 覆盖实体、UTF-8 与 GB18030 全角字母；无这些线索的正文
	// 不可能在编码转换后产生可识别的 ICP，因而无需校验整页 UTF-8。
	if metadataIndex(body, "&") >= 0 {
		return true
	}
	if at := metadataIndex(body, "\xef"); at >= 0 {
		for _, needle := range [...]string{"Ｉ", "ｉ", "Ｃ", "ｃ"} {
			if metadataIndex(body[at:], needle) >= 0 {
				return true
			}
		}
	}
	if at := metadataIndex(body, "\xa3"); at >= 0 {
		// UTF-8 中文也可能含 0xa3。逐个检查候选的后续字节，
		// 避免对大量普通中文重复搜索四种 GB18030 双字节序列。
		for at+1 < len(body) {
			switch body[at+1] {
			case 0xc9, 0xe9, 0xc3, 0xe3:
				return true
			}
			next := metadataIndex(body[at+1:], "\xa3")
			if next < 0 {
				break
			}
			at += next + 1
		}
	}
	if metadataIndex(body, "c") < 0 && metadataIndex(body, "C") < 0 {
		return false
	}
	upper, lower := metadataIndex(body, "I"), metadataIndex(body, "i")
	for upper >= 0 || lower >= 0 {
		at := upper
		if at < 0 || (lower >= 0 && lower < at) {
			at = lower
		}
		if at+1 < len(body) {
			next := body[at+1]
			if next == 'c' || next == 'C' || next == '<' || next >= 0x80 || metadataSpace(next) {
				return true
			}
		}
		if at == upper {
			n := metadataIndex(body[at+1:], "I")
			upper = -1
			if n >= 0 {
				upper = at + 1 + n
			}
		}
		if at == lower {
			n := metadataIndex(body[at+1:], "i")
			lower = -1
			if n >= 0 {
				lower = at + 1 + n
			}
		}
	}
	return false
}

func nextICPStart[S metadataSource](text S) int {
	next := -1
	for _, needle := range [...]string{"I", "i", "&", "\xef"} {
		if at := metadataIndex(text, needle); at >= 0 && (next < 0 || at < next) {
			next = at
		}
	}
	return next
}

func lastMetadataRune[S metadataSource](text S) (rune, int) {
	switch v := any(text).(type) {
	case string:
		return utf8.DecodeLastRuneInString(v)
	case []byte:
		return utf8.DecodeLastRune(v)
	}
	return utf8.RuneError, 1
}

func skipICPText[S metadataSource](m *icpMatcher, text S) {
	last, _ := lastMetadataRune(text)
	m.spaced = unicode.IsSpace(last) || last == 0x200b || last == 0xfeff
	for len(text) > 0 {
		switch v := any(text).(type) {
		case string:
			text = S(strings.TrimSpace(v))
		case []byte:
			text = S(bytes.TrimSpace(v))
		}
		if len(text) == 0 {
			break
		}
		r, size := lastMetadataRune(text)
		if r == 0x200b || r == 0xfeff {
			text = text[:len(text)-size]
			continue
		}
		m.prev = r
		return
	}
	m.spaced = true
}

func metadataRune[S metadataSource](body S) (rune, int) {
	switch v := any(body).(type) {
	case string:
		return utf8.DecodeRuneInString(v)
	case []byte:
		return utf8.DecodeRune(v)
	}
	return utf8.RuneError, 1
}

func extractICPText[S metadataSource](body S) string {
	lexer := metadataLexer[S]{body: body}
	var match icpMatcher
	official := false
	templateDepth := 0
	for {
		tok, ok := lexer.next()
		if !ok {
			break
		}
		if len(tok.name) == 0 {
			if templateDepth == 0 && !tok.raw {
				feedICPText(&match, tok.text, official)
			}
		} else if metadataEqualFold(tok.name, "template") {
			match.boundary()
			if tok.end {
				if templateDepth > 0 {
					templateDepth--
				}
			} else {
				templateDepth++
			}
		} else if templateDepth == 0 {
			if metadataEqualFold(tok.name, "a") {
				match.boundary()
				if tok.end {
					official = false
				} else {
					official = isICPAuthority(metadataAttribute(tok.attrs, "href"))
				}
			} else if isMetadataBlock(tok.name) || metadataEqualFold(tok.name, "script") || metadataEqualFold(tok.name, "style") {
				match.boundary()
			}
		}
		if match.authoritative != "" {
			return match.authoritative
		}
	}
	match.boundary()
	if match.authoritative != "" {
		return match.authoritative
	}
	return match.first
}

func isICPAuthority(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "" && !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https")) {
		return false
	}
	switch strings.ToLower(u.Hostname()) {
	case "beian.miit.gov.cn", "www.beian.miit.gov.cn", "beian.gov.cn", "www.beian.gov.cn", "miitbeian.gov.cn", "www.miitbeian.gov.cn":
		return true
	}
	return false
}

func isMetadataBlock[S metadataSource](tag S) bool {
	switch string(tag) {
	case "html", "body", "head", "div", "p", "section", "article", "aside", "nav", "footer", "header", "main", "li", "ul", "ol", "dl", "dt", "dd", "table", "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "pre", "blockquote":
		return true
	}
	// 借用的标签名称不在原正文中原地转换。
	for _, name := range [...]string{"html", "body", "head", "div", "p", "section", "article", "aside", "nav", "footer", "header", "main", "li", "ul", "ol", "dl", "dt", "dd", "table", "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "pre", "blockquote"} {
		if metadataEqualFold(tag, name) {
			return true
		}
	}
	return false
}

func feedICPText[S metadataSource](m *icpMatcher, text S, official bool) {
	for i := 0; i < len(text); {
		if m.state == 0 && text[i] != 'I' && text[i] != 'i' && text[i] != '&' && text[i] != 0xef {
			at := nextICPStart(text[i:])
			if at < 0 {
				skipICPText(m, text[i:])
				return
			}
			if at > 0 {
				m.spaced = false
				skipICPText(m, text[i:i+at])
				i += at
				continue
			}
		}
		if text[i] == '&' {
			end := i + 1
			for end < len(text) && end-i <= 40 {
				c := text[end]
				if c == ';' {
					end++
					break
				}
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '#') {
					break
				}
				end++
			}
			raw := string(text[i:end])
			decoded := html.UnescapeString(raw)
			if decoded != raw {
				for _, r := range decoded {
					m.feed(r, official)
				}
				i = end
				continue
			}
		}
		r, size := metadataRune(text[i:])
		m.feed(r, official)
		i += size
	}
}

// 识别状态只保存一个短候选。数字、字号和连接号可跨行内标签，块级
// 元素打断候选，避免把不同段落或脚本拼成备案号。
type icpMatcher struct {
	buf                      [96]byte
	n, state, digits, suffix int
	prev                     rune
	spaced, official         bool
	first, authoritative     string
}

func (m *icpMatcher) append(r rune) { m.n += utf8.EncodeRune(m.buf[m.n:], r) }
func icpProvince(r rune) bool {
	return strings.ContainsRune("京津冀晋蒙辽吉黑沪苏浙皖闽赣鲁豫鄂湘粤桂琼渝川蜀黔贵滇云藏陕秦甘陇青宁新", r)
}
func icpASCIIWord(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '/' || r == '.'
}

func (m *icpMatcher) commit() {
	if m.state != 6 && m.state != 8 {
		return
	}
	if m.official {
		m.authoritative = string(m.buf[:m.n])
	} else if m.first == "" {
		m.first = string(m.buf[:m.n])
	}
}
func (m *icpMatcher) boundary() { m.commit(); m.state = 0; m.n = 0; m.prev = 0; m.spaced = false }

func (m *icpMatcher) feed(r rune, official bool) {
	if r >= 0xff01 && r <= 0xff5e {
		r -= 0xfee0
	}
	if r == '備' {
		r = '备'
	}
	if r == '證' {
		r = '证'
	}
	if r == '號' {
		r = '号'
	}
	if unicode.IsSpace(r) || r == 0x200b || r == 0xfeff {
		m.spaced = true
		return
	}
	previous, spaced := m.prev, m.spaced
	m.prev = r
	m.spaced = false
	again := true
	for again {
		again = false
		switch m.state {
		case 0:
			if (r == 'I' || r == 'i') && (!icpASCIIWord(previous) || spaced) {
				m.n = 0
				m.digits = 0
				m.suffix = 0
				m.official = official
				if icpProvince(previous) {
					m.append(previous)
				}
				m.append(r)
				m.state = 1
			}
		case 1:
			if r == 'C' || r == 'c' {
				m.append(r)
				m.state = 2
			} else {
				m.state = 0
				again = true
			}
		case 2:
			if r == 'P' || r == 'p' {
				m.append(r)
				m.state = 3
			} else {
				m.state = 0
				again = true
			}
		case 3:
			if r == '备' || r == '证' {
				m.append(r)
				m.state = 4
			} else {
				m.state = 0
				again = true
			}
		case 4:
			if r >= '0' && r <= '9' && m.digits < 20 {
				m.append(r)
				m.digits++
			} else if m.digits > 0 && r == '号' {
				m.append(r)
				m.state = 6
			} else if m.digits > 0 && r == '-' {
				m.append(r)
				m.state = 5
			} else {
				m.state = 0
				again = true
			}
		case 5:
			if r >= '0' && r <= '9' && m.suffix < 10 {
				m.append(r)
				m.suffix++
			} else if m.suffix > 0 && r == '号' {
				m.append(r)
				m.state = 6
				m.suffix = 0
			} else {
				m.state = 0
				again = true
			}
		case 6:
			if r == '-' {
				m.append(r)
				m.state = 7
			} else {
				if r != '.' && r != '/' && r != '\\' && r != '_' && (spaced || !(r >= '0' && r <= '9')) {
					m.commit()
				}
				m.state = 0
				again = true
			}
		case 7:
			if r >= '0' && r <= '9' {
				m.append(r)
				m.suffix = 1
				m.state = 8
			} else {
				m.state = 0
				again = true
			}
		case 8:
			if r >= '0' && r <= '9' && m.suffix < 10 {
				m.append(r)
				m.suffix++
			} else {
				if r != '.' && r != '/' && r != '\\' && r != '_' && !(r >= '0' && r <= '9') {
					m.commit()
				}
				m.state = 0
				again = true
			}
		}
	}
}
