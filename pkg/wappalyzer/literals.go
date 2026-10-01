package wappalyzer

import (
	"github.com/cyberspacesec/gxx/v2/internal/literal"
	"regexp/syntax"
	"slices"
	"strings"
)

// requiredLiterals 提取一组 ASCII 字面量，成功匹配至少需要包含其中之一。
// 无法证明的分支不参与预筛选，最终判定仍使用上游的正则与版本提取器。
func requiredLiterals(source string) []string {
	pattern, _, _ := strings.Cut(source, `\;`)
	// 与 wappalyzergo v0.2.44 的 ParsePattern 展开规则保持一致。
	pattern = strings.ReplaceAll(pattern, `(\d+(?:\.\d+)+)`, "__verCap1__")
	pattern = strings.ReplaceAll(pattern, `((?:\d+\.)+\d+)`, "__verCap2__")
	pattern = strings.ReplaceAll(pattern, `\+`, "__escapedPlus__")
	pattern = strings.ReplaceAll(pattern, "+", "{1,250}")
	pattern = strings.ReplaceAll(pattern, "*", "{0,250}")
	pattern = strings.ReplaceAll(pattern, "__escapedPlus__", `\+`)
	pattern = strings.ReplaceAll(pattern, "__verCap1__", `(\d{1,20}(?:\.\d{1,20}){1,20})`)
	pattern = strings.ReplaceAll(pattern, "__verCap2__", `((?:\d{1,20}\.){1,20}\d{1,20})`)
	tree, err := syntax.Parse("(?i)"+pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	return literalsFromTree(tree)
}

func literalsFromTree(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if r > 127 {
				return nil
			}
		}
		if len(re.Rune) > 0 {
			return []string{strings.ToLower(string(re.Rune))}
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

type literalIndex struct{ *literal.Index }

func newLiteralIndex(words []string) *literalIndex         { return &literalIndex{literal.New(words)} }
func (idx *literalIndex) match(data string, bits []uint64) { idx.Match(data, bits) }
