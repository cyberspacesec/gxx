package literal

import "slices"

type literalNode struct {
	first, fail, outputLink uint32
	output                  int32
	count                   uint16
}
type literalEdge struct {
	next uint32
	char byte
}

// Index 是紧凑的 Aho-Corasick 索引。响应只遍历一次；连续数组避免
// 每条正则各扫描一遍正文，也避免每个字节节点持有独立 map 的常驻开销。
type Index struct {
	nodes []literalNode
	edges []literalEdge
	root  [256]uint32
}

func New(words []string) *Index {
	// 构造期也使用连续数组。每个节点的 map 会把短前缀放大为大量小对象，
	// 而大部分前缀只有一个后继；链式边足以完成插入，再整理为有序连续边。
	type buildNode struct{ first, out int32 }
	type buildEdge struct {
		sibling int32
		next    uint32
		char    byte
	}
	capacity := 1
	for _, word := range words {
		capacity += len(word)
	}
	nodes := make([]buildNode, 1, capacity)
	nodes[0] = buildNode{first: -1, out: -1}
	edges := make([]buildEdge, 0, capacity-1)
	for id, word := range words {
		var state uint32
		for i := 0; i < len(word); i++ {
			var next uint32
			for edge := nodes[state].first; edge >= 0; edge = edges[edge].sibling {
				if edges[edge].char == word[i] {
					next = edges[edge].next
					break
				}
			}
			if next == 0 {
				next = uint32(len(nodes))
				nodes = append(nodes, buildNode{first: -1, out: -1})
				edges = append(edges, buildEdge{sibling: nodes[state].first, next: next, char: word[i]})
				nodes[state].first = int32(len(edges) - 1)
			}
			state = next
		}
		nodes[state].out = int32(id)
	}
	idx := &Index{nodes: make([]literalNode, len(nodes)), edges: make([]literalEdge, 0, len(edges))}
	var children [256]literalEdge
	for i, node := range nodes {
		count := 0
		for edge := node.first; edge >= 0; edge = edges[edge].sibling {
			children[count] = literalEdge{next: edges[edge].next, char: edges[edge].char}
			count++
		}
		sorted := children[:count]
		slices.SortFunc(sorted, func(a, b literalEdge) int { return int(a.char) - int(b.char) })
		idx.nodes[i] = literalNode{first: uint32(len(idx.edges)), count: uint16(count), output: node.out}
		idx.edges = append(idx.edges, sorted...)
	}
	queue := make([]uint32, 0, len(nodes))
	for _, edge := range idx.edges[:idx.nodes[0].count] {
		idx.root[edge.char] = edge.next
		queue = append(queue, edge.next)
	}
	for head := 0; head < len(queue); head++ {
		state := queue[head]
		node := idx.nodes[state]
		for _, edge := range idx.edges[node.first : node.first+uint32(node.count)] {
			next, c := edge.next, edge.char
			fallback := idx.nodes[state].fail
			to := idx.step(fallback, c)
			for fallback != 0 && to == 0 {
				fallback = idx.nodes[fallback].fail
				to = idx.step(fallback, c)
			}
			idx.nodes[next].fail = to
			idx.nodes[next].outputLink = idx.nodes[to].outputLink
			if idx.nodes[to].output >= 0 {
				idx.nodes[next].outputLink = to
			}
			queue = append(queue, next)
		}
	}
	return idx
}

func (idx *Index) step(state uint32, c byte) uint32 {
	if state == 0 {
		return idx.root[c]
	}
	n := idx.nodes[state]
	edges := idx.edges[n.first : n.first+uint32(n.count)]
	for len(edges) > 0 {
		mid := len(edges) / 2
		if edges[mid].char == c {
			return edges[mid].next
		}
		if edges[mid].char < c {
			edges = edges[mid+1:]
		} else {
			edges = edges[:mid]
		}
	}
	return 0
}

func match[T ~string | ~[]byte](idx *Index, data T, bits []uint64) {
	clear(bits)
	var state uint32
	for i := 0; i < len(data); i++ {
		next := idx.step(state, data[i])
		for state != 0 && next == 0 {
			state = idx.nodes[state].fail
			next = idx.step(state, data[i])
		}
		state = next
		for node := state; node != 0; node = idx.nodes[node].outputLink {
			if id := idx.nodes[node].output; id >= 0 {
				bits[id/64] |= uint64(1) << uint(id%64)
			}
		}
	}
}

// Match 返回各字面量是否出现；words 必须为去重后的非空字面量。
// bits 由调用方独占，长度不得小于 (传入 New 的字面量数量+63)/64。
func (idx *Index) Match(data string, bits []uint64)      { match(idx, data, bits) }
func (idx *Index) MatchBytes(data []byte, bits []uint64) { match(idx, data, bits) }
