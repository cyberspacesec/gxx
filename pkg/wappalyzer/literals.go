package wappalyzer

import (
	"github.com/cyberspacesec/gxx/internal/literal"
	"regexp/syntax"
	"slices"
	"strings"
	"unicode/utf8"
)

// requiredLiterals 提取一组 ASCII 字面量，成功匹配至少需要包含其中之一。
// 无法证明的分支不参与预筛选，最终判定仍使用上游的正则与版本提取器。
func requiredLiterals(source string) []string {
	tree := parseUpstreamPattern(source)
	if tree == nil {
		return nil
	}
	return literalsFromTree(tree)
}

// requiredLiteralGroups 提取多组必要字面量：成功匹配必须同时满足每一组（每组至少出现一个）。
//
// 正则顶层是串接 A·B·C 时，任何匹配子串都由 A、B、C 各自的匹配依次拼成，因此
// literalsFromTree 对每一段给出的"至少含其一"条件同时成立，可以取合取。
// requiredLiterals 只挑其中一段；这里收集所有段，候选正则数量更少，判定结果不变。
// 单字节字面量几乎出现在每个页面中，不参与预筛选，只占用索引位。
func requiredLiteralGroups(source string) [][]string {
	tree := parseUpstreamPattern(source)
	if tree == nil {
		return nil
	}
	for tree.Op == syntax.OpCapture {
		tree = tree.Sub[0]
	}
	segments := []*syntax.Regexp{tree}
	if tree.Op == syntax.OpConcat {
		segments = tree.Sub
	}
	var groups [][]string
	for _, segment := range segments {
		words := literalsFromTree(segment)
		if len(words) == 0 || slices.ContainsFunc(words, func(word string) bool { return len(word) < 2 }) {
			continue
		}
		duplicate := slices.ContainsFunc(groups, func(group []string) bool { return slices.Equal(group, words) })
		if !duplicate {
			groups = append(groups, words)
		}
	}
	return groups
}

// parseUpstreamPattern 按 wappalyzergo 的展开规则得到上游实际编译的正则语法树。
func parseUpstreamPattern(source string) *syntax.Regexp {
	pattern, _, _ := strings.Cut(source, `\;`)
	tree, err := syntax.Parse("(?i)"+expandUpstreamPattern(pattern), syntax.Perl)
	if err != nil {
		return nil
	}
	return tree
}

func literalsFromTree(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		// 字面量含非 ASCII 字符时取其中最长的 ASCII 片段：整段字面量出现时，
		// 该片段必然随之出现，仍是必要条件。
		start, end, run := 0, 0, 0
		for i, r := range re.Rune {
			if r > 127 {
				run = i + 1
				continue
			}
			if i+1-run > end-start {
				start, end = run, i+1
			}
		}
		if end > start {
			return []string{strings.ToLower(string(re.Rune[start:end]))}
		}
	case syntax.OpCapture, syntax.OpPlus:
		return literalsFromTree(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min > 0 {
			return literalsFromTree(re.Sub[0])
		}
	case syntax.OpConcat:
		var best []string
		length := 0
		for _, child := range re.Sub {
			candidate := literalsFromTree(child)
			shortest := 0
			for i, word := range candidate {
				if i == 0 || len(word) < shortest {
					shortest = len(word)
				}
			}
			if shortest > length || shortest == length && len(candidate) < len(best) {
				best, length = candidate, shortest
			}
		}
		return best
	case syntax.OpAlternate:
		var words []string
		for _, branch := range re.Sub {
			candidate := literalsFromTree(branch)
			// 任一分支可在不含字面量时成立，就不能过滤整个正则。
			if len(candidate) == 0 {
				return nil
			}
			words = append(words, candidate...)
			if len(words) > 64 {
				return nil
			}
		}
		slices.Sort(words)
		return slices.Compact(words)
	}
	return nil
}

// maxWindowSpan 是可按窗口求值的模式的单次匹配字节数上限。上游把未转义的
// + 与 * 改写为最多 250 次重复，常见模式的匹配长度在 1–2 KiB 以内；
// 嵌套重复会放大到数十 KiB，那类模式继续整段求值。
const maxWindowSpan = 4 << 10

// matchSpan 返回模式单次匹配的最大字节数；0 表示不能按窗口求值。
//
// 只有长度有界、且不含行首行尾或词边界断言的模式才有确定的跨度：断言会读取
// 匹配区间之外的字符，截取窗口后结论可能改变。每个字符按 UTF-8 最长编码计。
func matchSpan(source string) int {
	tree := parseUpstreamPattern(source)
	if tree == nil {
		return 0
	}
	runes, ok := maxMatchRunes(tree)
	if !ok || runes == 0 || runes > maxWindowSpan/utf8.UTFMax {
		return 0
	}
	return runes * utf8.UTFMax
}

func maxMatchRunes(re *syntax.Regexp) (int, bool) {
	const limit = 1 << 20
	switch re.Op {
	case syntax.OpNoMatch, syntax.OpEmptyMatch:
		return 0, true
	case syntax.OpLiteral:
		return len(re.Rune), true
	case syntax.OpCharClass, syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		return 1, true
	case syntax.OpCapture, syntax.OpQuest:
		return maxMatchRunes(re.Sub[0])
	case syntax.OpRepeat:
		if re.Max < 0 {
			return 0, false
		}
		runes, ok := maxMatchRunes(re.Sub[0])
		if !ok || runes*re.Max > limit {
			return 0, false
		}
		return runes * re.Max, true
	case syntax.OpConcat:
		total := 0
		for _, sub := range re.Sub {
			runes, ok := maxMatchRunes(sub)
			if !ok || total+runes > limit {
				return 0, false
			}
			total += runes
		}
		return total, true
	case syntax.OpAlternate:
		longest := 0
		for _, sub := range re.Sub {
			runes, ok := maxMatchRunes(sub)
			if !ok {
				return 0, false
			}
			longest = max(longest, runes)
		}
		return longest, true
	}
	// 无界重复（* +）与各类位置断言。
	return 0, false
}

type literalIndex struct{ *literal.Index }

func newLiteralIndex(words []string) *literalIndex         { return &literalIndex{literal.New(words)} }
func (idx *literalIndex) match(data string, bits []uint64) { idx.Match(data, bits) }
