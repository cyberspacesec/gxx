package output

import (
	"github.com/cyberspacesec/gxx/utils/logger"
	"sync"
)

// 异步写入器把 URL 工作池的"格式化 + 落盘"动作从同步路径剥离，
// 由后台 goroutine 串行消费，避免高并发场景下抢占输出文件全局锁。
//
// 设计要点：
//   - URL worker 仅执行入队动作（O(1)），磁盘 IO 全部交给后台 writer；
//   - 队列容量有限，溢出时调用方应回退到同步写路径以保证不丢数据；
//   - asyncWriterCh 在整个生命周期内保持 open，关闭通过 asyncWriterDone
//     广播退出信号；writer 在退出前 drain 残余队列，保证全部落盘；
//   - submitAsync 与 disableAsyncWriter 之间不存在向已关闭 channel 发送的窗口。
//
// 由 InitOutput 成功打开文件后自动启用，CloseFileOutput 调用时自动停止。
var (
	asyncWriterCh      chan *WriteOptions
	asyncWriterDone    chan struct{}
	asyncWriterWG      sync.WaitGroup
	asyncWriterMu      sync.Mutex
	asyncWriterEnabled bool
)

// defaultAsyncQueueSize 异步队列默认容量。
// 经验值：与 URL 工作池容量 × 16 同量级，足以缓冲短时突发；过大会增加内存压力。
const defaultAsyncQueueSize = 1024

// enableAsyncWriter 启动后台 writer goroutine 与队列。
// 若已启用则直接返回，幂等安全。仅由 InitOutput 内部调用。
func enableAsyncWriter() {
	asyncWriterMu.Lock()
	defer asyncWriterMu.Unlock()

	if asyncWriterEnabled {
		return
	}

	asyncWriterCh = make(chan *WriteOptions, defaultAsyncQueueSize)
	asyncWriterDone = make(chan struct{})
	asyncWriterEnabled = true

	asyncWriterWG.Add(1)
	go asyncWriterLoop(asyncWriterCh, asyncWriterDone)

	logger.Debug("output 异步写入器已启用，队列容量=%d", defaultAsyncQueueSize)
}

// disableAsyncWriter 停止异步写入器并等待队列残余条目全部落盘。
//
// 通过关闭 done 通道通知 writer goroutine 退出，writer 在 drain
// 当前队列后返回。asyncWriterCh 始终保持 open，因此与 submitAsync
// 之间不会出现 send-on-closed-channel panic。
func disableAsyncWriter() {
	asyncWriterMu.Lock()
	if !asyncWriterEnabled {
		asyncWriterMu.Unlock()
		return
	}
	asyncWriterEnabled = false
	done := asyncWriterDone
	asyncWriterDone = nil
	asyncWriterMu.Unlock()

	close(done)
	asyncWriterWG.Wait()

	asyncWriterMu.Lock()
	asyncWriterCh = nil
	asyncWriterMu.Unlock()

	logger.Debug("output 异步写入器已停止，队列已 drain")
}

// submitAsync 把 opts 放入异步队列。
//
// 返回值含义：
//   - true：已成功入队；
//   - false：异步写入器未启用或队列已满，调用方应回退到同步写路径。
//
// 由于 asyncWriterCh 在生命周期内保持 open，本函数即便恰逢
// disableAsyncWriter 执行期间也不会触发 send-on-closed-channel panic。
func submitAsync(opts *WriteOptions) bool {
	asyncWriterMu.Lock()
	ch := asyncWriterCh
	enabled := asyncWriterEnabled
	defer asyncWriterMu.Unlock()

	if !enabled || ch == nil {
		return false
	}

	select {
	case ch <- opts:
		return true
	default:
		logger.Debug("output 异步队列已满，回退同步写入：target=%s", opts.Target)
		return false
	}
}

// asyncWriterLoop 单线程串行消费异步写入队列，
// 把磁盘 IO 完全从 URL 工作池剥离。
//
// done 关闭后进入 drain 阶段：以非阻塞方式消费 channel 内残余条目后退出，
// 保证重复调用 disable 也不会丢数据。
func asyncWriterLoop(ch chan *WriteOptions, done chan struct{}) {
	defer asyncWriterWG.Done()

	for {
		select {
		case opts := <-ch:
			if err := WriteFingerprints(opts); err != nil {
				logger.Error("异步写入失败: %v", err)
			}
		case <-done:
			drainAsyncQueue(ch)
			return
		}
	}
}

// drainAsyncQueue 在退出前尽量消费 channel 内残余条目（非阻塞）。
func drainAsyncQueue(ch chan *WriteOptions) {
	for {
		select {
		case opts := <-ch:
			if err := WriteFingerprints(opts); err != nil {
				logger.Error("异步写入失败: %v", err)
			}
		default:
			return
		}
	}
}
