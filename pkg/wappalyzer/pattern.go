package wappalyzer

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// compiledPattern 是一条上游模式的可执行形式。模式展开、置信度与版本模板的
// 解析以及版本提取，均与 wappalyzergo v0.3.9 的 ParsePattern / Evaluate 一致，
// 并由测试对全部上游模式逐条对照。
//
// 上游 Evaluate 每次调用都会把输入重新小写化并再做一遍字面量检查；这里的输入
// 已由必要字面量索引筛选，直接执行正则即可，结论相同。
type compiledPattern struct {
	regex      *regexp.Regexp
	confidence int
	version    string
	skipRegex  bool
}

// expandUpstreamPattern 把模式的正则部分展开为上游实际编译的表达式：
// 未转义的 + 与 * 改写为最多 250 次的有界重复，转义的 \+ 与 \* 保持字面量，
// 两种版本捕获写法改写为长度受限的等价形式。
func expandUpstreamPattern(pattern string) string {
	pattern = strings.ReplaceAll(pattern, `(\d+(?:\.\d+)+)`, "__verCap1__")
	pattern = strings.ReplaceAll(pattern, `((?:\d+\.)+\d+)`, "__verCap2__")
	pattern = strings.ReplaceAll(pattern, `\+`, "__escapedPlus__")
	pattern = strings.ReplaceAll(pattern, `\*`, "__escapedStar__")
	pattern = strings.ReplaceAll(pattern, "+", "{1,250}")
	pattern = strings.ReplaceAll(pattern, "*", "{0,250}")
	pattern = strings.ReplaceAll(pattern, "__escapedPlus__", `\+`)
	pattern = strings.ReplaceAll(pattern, "__escapedStar__", `\*`)
	pattern = strings.ReplaceAll(pattern, "__verCap1__", `(\d{1,20}(?:\.\d{1,20}){1,20})`)
	pattern = strings.ReplaceAll(pattern, "__verCap2__", `((?:\d{1,20}\.){1,20}\d{1,20})`)
	return pattern
}

func compilePattern(source string) (*compiledPattern, error) {
	parts := strings.Split(source, `\;`)
	p := &compiledPattern{confidence: 100, skipRegex: parts[0] == ""}
	if !p.skipRegex {
		regex, err := regexp.Compile("(?i)" + expandUpstreamPattern(parts[0]))
		if err != nil {
			return nil, err
		}
		p.regex = regex
	}
	for _, part := range parts[1:] {
		key, value, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		switch key {
		case "confidence":
			// 无法解析的置信度按默认值处理。
			p.confidence = 100
			if n, err := strconv.Atoi(value); err == nil {
				p.confidence = n
			}
		case "version":
			p.version = value
		}
	}
	return p, nil
}

// evaluate 返回 target 是否命中以及提取到的版本。
func (p *compiledPattern) evaluate(target string) (bool, string) {
	if p.skipRegex {
		return true, ""
	}
	// 没有版本模板时不需要捕获组，判断是否匹配即可。
	if p.version == "" {
		return p.regex.MatchString(target), ""
	}
	submatches := p.regex.FindStringSubmatch(target)
	if len(submatches) == 0 {
		return false, ""
	}
	return true, p.extractVersion(submatches[1:])
}

// extractVersion 用捕获组填充版本模板并求值其中的三元表达式；模板无效时版本为空。
func (p *compiledPattern) extractVersion(groups []string) string {
	result := p.version
	for i, group := range groups {
		result = strings.ReplaceAll(result, fmt.Sprintf(`\%d`, i+1), group)
	}
	if !strings.Contains(result, "?") {
		return strings.TrimSpace(result)
	}
	// 三元表达式形如 `条件?真值:假值`，只判断是否存在捕获组。
	parts := strings.Split(result, "?")
	if len(parts) != 2 {
		return ""
	}
	branches := strings.Split(parts[1], ":")
	if len(branches) != 2 {
		return ""
	}
	switch {
	case branches[0] != "":
		if len(groups) == 0 {
			result = branches[1]
		} else {
			result = branches[0]
		}
	case branches[1] == "":
		result = ""
		if len(groups) != 0 {
			result = branches[0]
		}
	default:
		result = branches[1]
	}
	return strings.TrimSpace(result)
}
