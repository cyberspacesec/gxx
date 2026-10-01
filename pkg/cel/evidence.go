package cel

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cyberspacesec/gxx/v2/utils/proto"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"
	"github.com/google/cel-go/parser"
)

const (
	maxTracePredicates = 128
	maxEvidence        = 16
	maxEvidenceSnippet = 256
)

// Evidence 的位置是原始字段的字节区间 [Start, End)。-1 表示没有可定位内容。
// 二进制片段以 base64 保存；SnippetStart 始终使用解码前的字节位置。
type Evidence struct {
	Expression   string `json:"expression"`
	Field        string `json:"field,omitempty"`
	Matched      bool   `json:"matched"`
	Start        int    `json:"start"`
	End          int    `json:"end"`
	SnippetStart int    `json:"snippet_start"`
	Snippet      string `json:"snippet,omitempty"`
	Encoding     string `json:"encoding,omitempty"`
	Truncated    bool   `json:"truncated,omitempty"`
}

// 只追踪布尔值，不保存 ref.Val 或响应体。每次求值独占固定大小的追踪区。
type evaluationTrace struct{ values [maxTracePredicates]uint8 }
type evidenceOperation uint8

const (
	evidencePredicate evidenceOperation = iota
	evidenceLiteral
	evidenceAnd
	evidenceOr
	evidenceNot
)

type evidenceNode struct {
	text      string
	field     string
	operation string
	literal   []byte
	regex     *regexp.Regexp
	children  []int
	kind      evidenceOperation
	value     uint8
}
type evidencePlan struct {
	indices   map[int64]int
	nodes     []evidenceNode
	truncated bool
}

func newEvidencePlan(tree *cel.Ast) *evidencePlan {
	p := &evidencePlan{indices: make(map[int64]int)}
	root := tree.NativeRep().Expr()
	ast.PreOrderVisit(root, ast.NewExprVisitor(func(expression ast.Expr) {
		if tree.NativeRep().GetType(expression.ID()) != types.BoolType {
			return
		}
		if len(p.nodes) == maxTracePredicates {
			p.truncated = true
			return
		}
		text, _ := parser.Unparse(expression, tree.NativeRep().SourceInfo())
		p.indices[expression.ID()] = len(p.nodes)
		node := evidenceNode{text: clipEvidenceText(text, 512)}
		node.field, node.operation, node.literal = predicateParts(expression)
		if expression.Kind() == ast.LiteralKind {
			node.kind, node.value = evidenceLiteral, 1
			if value, ok := expression.AsLiteral().(types.Bool); ok && bool(value) {
				node.value = 2
			}
		}
		if expression.Kind() == ast.CallKind {
			switch expression.AsCall().FunctionName() {
			case operators.LogicalAnd:
				node.kind = evidenceAnd
			case operators.LogicalOr:
				node.kind = evidenceOr
			case operators.LogicalNot:
				node.kind = evidenceNot
			}
		}
		if node.operation == "matches" && node.literal != nil {
			node.regex, _ = regexp.Compile(string(node.literal))
		}
		p.nodes = append(p.nodes, node)
	}))
	// 程序执行只需字段、字面量和逻辑关系，完整 AST 不随证据计划保留。
	ast.PreOrderVisit(root, ast.NewExprVisitor(func(expression ast.Expr) {
		index, found := p.indices[expression.ID()]
		if !found || p.nodes[index].kind < evidenceAnd {
			return
		}
		for _, argument := range expression.AsCall().Args() {
			child, found := p.indices[argument.ID()]
			if !found {
				child = -1
			}
			p.nodes[index].children = append(p.nodes[index].children, child)
		}
	}))
	return p
}

type evidenceStep struct {
	interpreter.InterpretableV2
	index int
}

func (s *evidenceStep) Exec(frame *interpreter.ExecutionFrame) ref.Val {
	value := s.InterpretableV2.Exec(frame)
	if result, ok := value.(types.Bool); ok {
		if state, found := frame.ResolveName(contextVariable); found {
			if current, ok := state.(*evaluationContext); ok && current.trace != nil {
				current.trace.values[s.index] = 1
				if bool(result) {
					current.trace.values[s.index] = 2
				}
			}
		}
	}
	return value
}
func (s *evidenceStep) Eval(activation interpreter.Activation) ref.Val {
	frame, err := interpreter.NewExecutionFrame(activation)
	if err != nil {
		return types.NewErr("%v", err)
	}
	defer frame.Pop()
	return s.Exec(frame)
}
func (p *evidencePlan) decorate(step interpreter.InterpretableV2) (interpreter.InterpretableV2, error) {
	index, tracked := -1, false
	if p != nil {
		index, tracked = p.indices[step.ID()]
	}
	if call, ok := step.(interpreter.InterpretableCall); ok {
		name := call.Function()
		if (name == "__gxx_bcontains" || name == "__gxx_ibcontains") && len(call.Args()) == 3 {
			if !tracked {
				index = -1
			}
			return &responseContainsStep{InterpretableCall: call, index: index, fold: name == "__gxx_ibcontains"}, nil
		}
		if name == operators.LogicalAnd || name == operators.LogicalOr || name == operators.LogicalNot {
			return step, nil
		}
	}
	if tracked && p.nodes[index].kind != evidenceLiteral {
		return &evidenceStep{step, index}, nil
	}
	return step, nil
}

// 三参数的响应查找直接执行已完成类型检查的调用，避免每次构造 []ref.Val。
// 参数按原顺序各求值一次，错误与 unknown 的传播遵循 CEL 严格函数语义。
type responseContainsStep struct {
	interpreter.InterpretableCall
	index int
	fold  bool
}

func (s *responseContainsStep) Exec(frame *interpreter.ExecutionFrame) ref.Val {
	var values [3]ref.Val
	var unknown *types.Unknown
	for index, argument := range s.Args() {
		values[index] = argument.Exec(frame)
		if types.IsError(values[index]) {
			return values[index]
		}
		unknown, _ = types.MaybeMergeUnknowns(values[index], unknown)
	}
	if unknown != nil {
		return unknown
	}
	state, ok := values[0].Value().(*evaluationContext)
	if !ok {
		return types.NewErrWithNodeID(s.ID(), "缺少执行上下文")
	}
	value, valueOK := values[1].(types.Bytes)
	needle, needleOK := values[2].(types.Bytes)
	if !valueOK || !needleOK {
		return types.NewErrWithNodeID(s.ID(), "响应查找参数必须为 bytes")
	}
	matched := containsResponse(state.ctx, value, needle, s.fold)
	if s.index >= 0 && state.trace != nil {
		state.trace.values[s.index] = 1
		if matched {
			state.trace.values[s.index] = 2
		}
	}
	return types.Bool(matched)
}
func (s *responseContainsStep) Eval(activation interpreter.Activation) ref.Val {
	frame, err := interpreter.NewExecutionFrame(activation)
	if err != nil {
		return types.NewErr("%v", err)
	}
	defer frame.Pop()
	return s.Exec(frame)
}

func (p *evidencePlan) value(index int, trace *evaluationTrace) uint8 {
	if index < 0 || index >= len(p.nodes) {
		return 0
	}
	node := &p.nodes[index]
	switch node.kind {
	case evidenceLiteral:
		return node.value
	case evidenceNot:
		if len(node.children) == 1 {
			if value := p.value(node.children[0], trace); value != 0 {
				return 3 - value
			}
		}
		return 0
	case evidenceAnd, evidenceOr:
		and := node.kind == evidenceAnd
		complete := true
		for _, argument := range node.children {
			value := p.value(argument, trace)
			if and && value == 1 {
				return 1
			}
			if !and && value == 2 {
				return 2
			}
			complete = complete && value != 0
		}
		if complete {
			if and {
				return 2
			}
			return 1
		}
		return 0
	}
	return trace.values[index]
}

func (c *CustomLib) SetEvidenceEnabled(enabled bool) { c.evidenceEnabled = enabled }

// Evidence 必须在相应表达式求值之后、下一次求值之前读取。
// 仅沿实际执行且符合逻辑结果的分支取证，不重新执行 CEL 或其 I/O、随机函数。
func (c *CustomLib) Evidence(variables map[string]any) ([]Evidence, bool) {
	p := c.lastTrace
	if p == nil || !c.evidenceEnabled {
		return nil, false
	}
	var result []Evidence
	truncated := p.truncated
	var visit func(int)
	visit = func(index int) {
		value := p.value(index, &c.trace)
		if value == 0 {
			return
		}
		if len(result) == maxEvidence {
			truncated = true
			return
		}
		matched := value == 2
		node := &p.nodes[index]
		switch node.kind {
		case evidenceAnd, evidenceOr:
			for _, argument := range node.children {
				childValue := p.value(argument, &c.trace)
				if childValue != 0 && (childValue == 2) == matched {
					visit(argument)
				}
			}
			return
		case evidenceNot:
			for _, argument := range node.children {
				visit(argument)
			}
			return
		}
		evidence := Evidence{Expression: node.text, Matched: matched, Start: -1, End: -1, SnippetStart: -1}
		field, operation, literal := node.field, node.operation, node.literal
		evidence.Field = field
		if data, ok := evidenceField(variables, field); ok {
			start, end := -1, -1
			if matched && literal != nil {
				switch operation {
				case "contains", "bcontains", "__gxx_bcontains", "startsWith", "bstartsWith", operators.Equals:
					start = bytes.Index(data, literal)
					if start >= 0 {
						end = start + len(literal)
					}
				case "icontains", "ibcontains", "__gxx_ibcontains":
					start = bytes.Index(lowerResponse(c.requests.ctx, data), bytes.ToLower(literal))
					if start >= 0 {
						start, end = originalFoldRange(data, start, start+len(bytes.ToLower(literal)))
					}
				case "matches":
					if node.regex != nil {
						if offsets := node.regex.FindIndex(data); offsets != nil {
							start, end = offsets[0], offsets[1]
						}
					}
				case "bmatches", "__gxx_bmatches":
					if re, err := getCachedRegexp2(string(literal), 0); err == nil {
						if match, err := re.FindRunesMatch(regexResponseRunes(c.requests.ctx, data)); err == nil && match != nil {
							start, end = runeByteOffset(data, match.Index), runeByteOffset(data, match.Index+match.Length)
						}
					}
				}
			}
			if start >= 0 && end >= start {
				setEvidenceSnippet(&evidence, data, start, end)
			}
		}
		result = append(result, evidence)
	}
	visit(0)
	return result, truncated
}

func predicateParts(expression ast.Expr) (string, string, []byte) {
	if expression.Kind() != ast.CallKind {
		return evidencePath(expression), "", nil
	}
	call := expression.AsCall()
	arguments := call.Args()
	if call.IsMemberFunction() {
		arguments = append([]ast.Expr{call.Target()}, arguments...)
	}
	var field string
	var literal []byte
	for _, argument := range arguments {
		if path := evidencePath(argument); strings.HasPrefix(path, "response.") || strings.HasPrefix(path, "request.") {
			field = path
		}
		if argument.Kind() == ast.LiteralKind {
			switch value := argument.AsLiteral().(type) {
			case types.Bytes:
				literal = []byte(value)
			case types.String:
				literal = []byte(value)
			case types.Int:
				literal = []byte(fmt.Sprint(int64(value)))
			}
		}
	}
	return field, call.FunctionName(), literal
}
func evidencePath(expression ast.Expr) string {
	switch expression.Kind() {
	case ast.IdentKind:
		return expression.AsIdent()
	case ast.SelectKind:
		selection := expression.AsSelect()
		if path := evidencePath(selection.Operand()); path != "" {
			return path + "." + selection.FieldName()
		}
	case ast.CallKind:
		call := expression.AsCall()
		if call.FunctionName() == operators.Index && len(call.Args()) == 2 && call.Args()[1].Kind() == ast.LiteralKind {
			if value, ok := call.Args()[1].AsLiteral().(types.String); ok {
				return evidencePath(call.Args()[0]) + "." + string(value)
			}
		}
		if (call.FunctionName() == "string" || call.FunctionName() == "bytes") && len(call.Args()) == 1 {
			return evidencePath(call.Args()[0])
		}
	}
	return ""
}

func evidenceField(variables map[string]any, field string) ([]byte, bool) {
	if response, ok := variables["response"].(*proto.Response); ok && strings.HasPrefix(field, "response.") {
		switch field {
		case "response.body":
			return response.Body, true
		case "response.raw":
			return response.Raw, true
		case "response.raw_header":
			return response.RawHeader, true
		case "response.icon_hash":
			return []byte(response.IconHash), true
		case "response.content_type":
			return []byte(response.ContentType), true
		case "response.status":
			return []byte(fmt.Sprint(response.Status)), true
		}
		if key, ok := strings.CutPrefix(field, "response.headers."); ok {
			value, found := response.Headers[key]
			return []byte(value), found
		}
	}
	if request, ok := variables["request"].(*proto.Request); ok {
		switch field {
		case "request.body":
			return request.Body, true
		case "request.raw":
			return request.Raw, true
		case "request.raw_header":
			return request.RawHeader, true
		case "request.method":
			return []byte(request.Method), true
		}
		if key, ok := strings.CutPrefix(field, "request.headers."); ok {
			value, found := request.Headers[key]
			return []byte(value), found
		}
	}
	return nil, false
}

func setEvidenceSnippet(evidence *Evidence, data []byte, start, end int) {
	from := max(0, start-48)
	to := min(len(data), from+maxEvidenceSnippet)
	textFrom, textTo := from, to
	for textFrom < start && !utf8.RuneStart(data[textFrom]) {
		textFrom++
	}
	for textTo > textFrom && textTo < len(data) && !utf8.RuneStart(data[textTo]) {
		textTo--
	}
	if utf8.Valid(data[textFrom:textTo]) {
		from, to = textFrom, textTo
		evidence.Snippet = string(data[from:to])
		evidence.Encoding = "utf-8"
	} else {
		evidence.Snippet = base64.StdEncoding.EncodeToString(data[from:to])
		evidence.Encoding = "base64"
	}
	evidence.Start, evidence.End, evidence.SnippetStart = start, end, from
	evidence.Truncated = end > to
}

func clipEvidenceText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	for limit > 0 && !utf8.RuneStart(value[limit]) {
		limit--
	}
	return strings.Clone(value[:limit])
}
func runeByteOffset(data []byte, runes int) int {
	index := 0
	for runes > 0 && index < len(data) {
		_, size := utf8.DecodeRune(data[index:])
		index += size
		runes--
	}
	return index
}
func originalFoldRange(data []byte, start, end int) (int, int) {
	if bytes.IndexFunc(data[:min(end, len(data))], func(value rune) bool { return value >= utf8.RuneSelf }) < 0 {
		return start, end
	}
	original, folded, from, to := 0, 0, -1, -1
	for original < len(data) {
		value, size := utf8.DecodeRune(data[original:])
		if folded == start {
			from = original
		}
		folded += utf8.RuneLen(unicode.ToLower(value))
		original += size
		if folded == end {
			to = original
			break
		}
	}
	return from, to
}
