package finger

import (
	"bytes"
	"html"
	"io"
	"strings"

	nethtml "golang.org/x/net/html"
)

type metadataSource interface{ string | []byte }

func metadataIndex[S metadataSource](s S, sub string) int {
	switch v := any(s).(type) {
	case string:
		return strings.Index(v, sub)
	case []byte:
		return bytes.Index(v, []byte(sub))
	}
	return -1
}

func metadataEqualFold[S metadataSource](s S, want string) bool {
	if len(s) != len(want) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != want[i] {
			return false
		}
	}
	return true
}

func metadataSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' }

type metadataToken[S metadataSource] struct {
	name, attrs, text S
	end, raw          bool
}

// metadataLexer 借用输入切片，只读取元数据所需的标签和文本。
// 长文本不进入 DOM 或可增长的 token 缓冲；属性引号、注释和原始文本区
// 单独处理，脚本内的伪标签不会作为页面资源。
type metadataLexer[S metadataSource] struct {
	body   S
	pos    int
	rawTag string
}

func (l *metadataLexer[S]) next() (metadataToken[S], bool) {
	var token metadataToken[S]
	for l.pos < len(l.body) {
		start := l.pos
		if l.rawTag != "" {
			end := len(l.body)
			for at := start; at < len(l.body); {
				if l.rawTag == "plaintext" {
					break
				}
				i := metadataIndex(l.body[at:], "</")
				if i < 0 {
					break
				}
				at += i
				n := at + 2 + len(l.rawTag)
				if n <= len(l.body) && metadataEqualFold(l.body[at+2:n], l.rawTag) && (n == len(l.body) || metadataSpace(l.body[n]) || l.body[n] == '>' || l.body[n] == '/') {
					end = at
					break
				}
				at += 2
			}
			if l.rawTag == "script" && metadataIndex(l.body[start:end], "<!--") >= 0 {
				end = start + metadataScriptLength(l.body[start:])
			}
			l.rawTag = ""
			if end > start {
				l.pos = end
				token.text = l.body[start:end]
				token.raw = true
				return token, true
			}
		}
		if l.body[start] != '<' {
			i := metadataIndex(l.body[start:], "<")
			if i < 0 {
				i = len(l.body) - start
			}
			l.pos = start + i
			token.text = l.body[start:l.pos]
			return token, true
		}
		if len(l.body)-start >= 4 && string(l.body[start:start+4]) == "<!--" {
			end := start + 4
			if end < len(l.body) && l.body[end] == '>' {
				l.pos = end + 1
				continue
			}
			if end+1 < len(l.body) && l.body[end] == '-' && l.body[end+1] == '>' {
				l.pos = end + 2
				continue
			}
			i := metadataIndex(l.body[end:], "-->")
			comment := l.body[end:]
			if i >= 0 {
				comment = comment[:i+3]
			}
			j := metadataIndex(comment, "--!>")
			width := 3
			if j >= 0 && (i < 0 || j < i) {
				i = j
				width = 4
			}
			if i < 0 {
				l.pos = len(l.body)
				return token, false
			}
			l.pos = end + i + width
			continue
		}
		at := start + 1
		if at < len(l.body) && (l.body[at] == '!' || l.body[at] == '?') {
			i := metadataIndex(l.body[at:], ">")
			if i < 0 {
				l.pos = len(l.body)
				return token, false
			}
			l.pos = at + i + 1
			continue
		}
		if at < len(l.body) && l.body[at] == '/' {
			token.end = true
			at++
		}
		nameStart := at
		if at < len(l.body) && !(l.body[at] >= 'a' && l.body[at] <= 'z' || l.body[at] >= 'A' && l.body[at] <= 'Z') {
			l.pos = start + 1
			token.text = l.body[start:l.pos]
			return token, true
		}
		for at < len(l.body) && !metadataSpace(l.body[at]) && l.body[at] != '/' && l.body[at] != '>' {
			at++
		}
		if at == nameStart {
			l.pos = start + 1
			token.text = l.body[start:l.pos]
			return token, true
		}
		token.name = l.body[nameStart:at]
		attrStart := at
		var quote byte
		state := 0
		for at < len(l.body) {
			c := l.body[at]
			if state != 4 && c == '>' {
				break
			}
			switch state {
			case 0:
				if !metadataSpace(c) && c != '/' {
					state = 1
				}
			case 1:
				if c == '=' {
					state = 3
				} else if metadataSpace(c) {
					state = 2
				}
			case 2:
				if c == '=' {
					state = 3
				} else if !metadataSpace(c) {
					state = 1
				}
			case 3:
				if c == '\'' || c == '"' {
					quote = c
					state = 4
				} else if !metadataSpace(c) {
					state = 5
				}
			case 4:
				if c == quote {
					state = 0
				}
			case 5:
				if metadataSpace(c) {
					state = 0
				}
			}
			at++
		}
		if at == len(l.body) {
			l.pos = at
			return metadataToken[S]{}, false
		}
		token.attrs = l.body[attrStart:at]
		l.pos = at + 1
		if !token.end {
			for _, tag := range [...]string{"script", "style", "title", "textarea", "xmp", "iframe", "noembed", "noframes", "plaintext"} {
				if metadataEqualFold(token.name, tag) {
					l.rawTag = tag
					break
				}
			}
		}
		return token, true
	}
	return token, false
}

// 脚本的转义注释状态交给标准 HTML tokenizer；普通脚本仍借用原正文。
func metadataScriptLength[S metadataSource](body S) int {
	var reader io.Reader
	switch v := any(body).(type) {
	case string:
		reader = strings.NewReader(v)
	case []byte:
		reader = bytes.NewReader(v)
	}
	z := nethtml.NewTokenizer(io.MultiReader(strings.NewReader("<script>"), reader))
	z.Next()
	switch z.Next() {
	case nethtml.TextToken:
		return len(z.Raw())
	case nethtml.EndTagToken:
		return 0
	}
	return len(body)
}

// metadataAttribute 保留第一个同名属性，与浏览器的重复属性处理一致。
// 只复制调用方需要的值，返回内容不引用原始页面。
func metadataAttribute[S metadataSource](attrs S, want string) string {
	for at := 0; at < len(attrs); {
		for at < len(attrs) && (metadataSpace(attrs[at]) || attrs[at] == '/') {
			at++
		}
		start := at
		for at < len(attrs) && !metadataSpace(attrs[at]) && attrs[at] != '=' && attrs[at] != '/' {
			at++
		}
		if start == at {
			at++
			continue
		}
		key := attrs[start:at]
		for at < len(attrs) && metadataSpace(attrs[at]) {
			at++
		}
		var val S
		if at < len(attrs) && attrs[at] == '=' {
			at++
			for at < len(attrs) && metadataSpace(attrs[at]) {
				at++
			}
			if at < len(attrs) && (attrs[at] == '\'' || attrs[at] == '"') {
				quote := attrs[at]
				at++
				start = at
				for at < len(attrs) && attrs[at] != quote {
					at++
				}
				val = attrs[start:at]
				if at < len(attrs) {
					at++
				}
			} else {
				start = at
				for at < len(attrs) && !metadataSpace(attrs[at]) {
					at++
				}
				val = attrs[start:at]
			}
		}
		if metadataEqualFold(key, want) {
			return decodeMetadataAttribute(val)
		}
	}
	return ""
}

func ownedMetadataString[S metadataSource](val S) string {
	switch v := any(val).(type) {
	case string:
		return strings.Clone(v)
	case []byte:
		return string(v)
	}
	return ""
}

func decodeMetadataAttribute[S metadataSource](val S) string {
	if metadataIndex(val, "\x00") >= 0 || metadataIndex(val, "\r") >= 0 {
		raw := strings.ReplaceAll(string(val), "\x00", "\ufffd")
		raw = strings.ReplaceAll(strings.ReplaceAll(raw, "\r\n", "\n"), "\r", "\n")
		return decodeMetadataAttribute(raw)
	}
	if metadataIndex(val, "&") < 0 {
		return ownedMetadataString(val)
	}
	raw := string(val)
	decoded := html.UnescapeString(raw)
	if decoded == raw {
		return ownedMetadataString(val)
	}
	// 常见完整实体直接解码；其余交给属性上下文，避免把签名参数
	// 中的 &notit= 等片段按照普通文本实体规则改写。
	basic := true
	for at := 0; at < len(raw); {
		i := strings.IndexByte(raw[at:], '&')
		if i < 0 {
			break
		}
		at += i
		found := false
		for _, entity := range [...]string{"&amp;", "&quot;", "&apos;", "&lt;", "&gt;", "&nbsp;"} {
			if strings.HasPrefix(raw[at:], entity) {
				at += len(entity)
				found = true
				break
			}
		}
		if !found {
			basic = false
			break
		}
	}
	if basic {
		return decoded
	}
	z := nethtml.NewTokenizer(strings.NewReader(`<a v="` + strings.ReplaceAll(raw, `"`, `&#34;`) + `">`))
	if z.Next() == nethtml.StartTagToken {
		z.TagName()
		_, value, _ := z.TagAttr()
		return string(value)
	}
	return ownedMetadataString(val)
}
