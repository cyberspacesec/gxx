package network

import (
	"context"
	"io"
	"net/http"
	"sync"
)

// ReadResponseBodyLimit 与 ReadResponseBody 相同，并报告正文是否超过上限而被截断。
// 声明了长度时按声明判断；长度未知且恰好读满上限时视为可能被截断。不为判断多读字节。
func ReadResponseBodyLimit(resp *http.Response, limit int64) ([]byte, bool, error) {
	data, err := ReadResponseBody(resp, limit)
	if limit <= 0 || int64(len(data)) < limit {
		return data, false, err
	}
	if resp.ContentLength >= 0 {
		return data, resp.ContentLength > limit, err
	}
	return data, true, err
}

type truncationKey struct{}

// truncationTracker 记录一次扫描中正文被截断的响应对象。
type truncationTracker struct {
	mu    sync.Mutex
	items map[any]struct{}
}

// WithTruncationTracker 让 ctx 下构造的响应对象记录正文是否被截断。
func WithTruncationTracker(ctx context.Context) context.Context {
	return context.WithValue(ctx, truncationKey{}, &truncationTracker{})
}

// MarkTruncated 记录响应对象 value 的正文超过读取上限；ctx 没有记录器时不做任何事。
func MarkTruncated(ctx context.Context, value any) {
	tracker, _ := ctx.Value(truncationKey{}).(*truncationTracker)
	if tracker == nil || value == nil {
		return
	}
	tracker.mu.Lock()
	if tracker.items == nil {
		tracker.items = make(map[any]struct{})
	}
	tracker.items[value] = struct{}{}
	tracker.mu.Unlock()
}

// Truncated 报告响应对象 value 的正文是否被截断。
func Truncated(ctx context.Context, value any) bool {
	tracker, _ := ctx.Value(truncationKey{}).(*truncationTracker)
	if tracker == nil || value == nil {
		return false
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	_, ok := tracker.items[value]
	return ok
}

// ReadResponseBody 在字节上限内读取响应。长度声明只用于容量提示；未知
// 长度使用分段暂存，EOF 后一次合并，不把可复用的暂存区交给调用方。
func ReadResponseBody(resp *http.Response, limit int64) ([]byte, error) {
	reader := io.LimitReader(resp.Body, limit)
	if limit <= 0 {
		return io.ReadAll(reader)
	}
	if resp.ContentLength <= 0 {
		return readUnknownBody(reader, limit)
	}
	size := min(resp.ContentLength, limit)
	// 长度声明来自远端。先确认响应超过小缓冲，避免短错误页或提前断流
	// 仅凭一个夸大的 Content-Length 就占满整个响应预算。
	data := make([]byte, min(size, 4096))
	read := 0
	for {
		if read == len(data) {
			if int64(read) == limit {
				return data, nil
			}
			if int64(len(data)) == size {
				// 自定义 RoundTripper 可能返回与 ContentLength 不同的实际正文。
				rest, err := io.ReadAll(reader)
				return append(data, rest...), err
			}
			var next [1]byte
			n, err := reader.Read(next[:])
			if n > 0 {
				grown := make([]byte, size)
				copy(grown, data)
				grown[read] = next[0]
				read++
				data = grown
			}
			if err != nil {
				if err == io.EOF {
					err = nil
				}
				return data[:read], err
			}
			continue
		}
		n, err := reader.Read(data[read:])
		read += n
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return data[:read], err
		}
	}
}

const bodyChunkSize = 32 << 10

// 最多常驻 1 MiB。并发请求各自独占暂存块，超出池容量的块随读取结束释放。
var bodyChunks = make(chan *[bodyChunkSize]byte, 32)

func acquireBodyChunk() *[bodyChunkSize]byte {
	select {
	case block := <-bodyChunks:
		return block
	default:
		return new([bodyChunkSize]byte)
	}
}

func releaseBodyChunk(block *[bodyChunkSize]byte) {
	select {
	case bodyChunks <- block:
	default:
	}
}

// fillBody 保留 Reader 返回的真实错误；io.ReadFull 合成的 UnexpectedEOF
// 不能用于这里，否则会混淆正常 EOF 与 HTTP 提前断流。
func fillBody(reader io.Reader, data []byte) (int, error) {
	read := 0
	for read < len(data) {
		n, err := reader.Read(data[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

func readUnknownBody(reader io.Reader, limit int64) ([]byte, error) {
	first := make([]byte, min(limit, 512))
	read, err := fillBody(reader, first)
	first = first[:read]
	if err != nil || int64(read) == limit {
		if err == io.EOF {
			err = nil
		}
		return first, err
	}
	type segment struct {
		block *[bodyChunkSize]byte
		size  int
	}
	// 默认正文上限只需要 16 块；更大的显式上限仍可扩展，不改变读取范围。
	var storage [16]segment
	segments := storage[:0]
	defer func() {
		for _, part := range segments {
			releaseBodyChunk(part.block)
		}
	}()
	total := int64(read)
	for total < limit && err == nil {
		block := acquireBodyChunk()
		n, readErr := fillBody(reader, block[:min(int64(bodyChunkSize), limit-total)])
		if n > 0 {
			segments = append(segments, segment{block, n})
		} else {
			releaseBodyChunk(block)
		}
		total += int64(n)
		err = readErr
	}
	if err == io.EOF {
		err = nil
	}
	if len(segments) == 0 {
		return first, err
	}
	data := make([]byte, total)
	n := copy(data, first)
	for _, part := range segments {
		n += copy(data[n:], part.block[:part.size])
	}
	return data, err
}
