/*
Package runner CLI 风格批量扫描辅助函数：进度条、URL 工作池、汇总报告。

SDK 用户通常不使用本文件中的能力，而是直接调用 (*Runner).ScanTarget；
本文件是为 cmd/cli 入口提供的便捷封装。
*/
package runner

import (
	"bufio"
	"context"
	"fmt"
	"github.com/cyberspacesec/gxx/v2/types"
	"github.com/cyberspacesec/gxx/v2/utils/common"
	"github.com/cyberspacesec/gxx/v2/utils/logger"
	"github.com/cyberspacesec/gxx/v2/utils/output"
	"os"
	"strings"
	"sync"
	"time"
)

// LoadTargets 从命令行参数或目标文件中读取目标列表（带去重）。
func LoadTargets(options *types.CmdOptions) []string {
	if len(options.Target) > 0 {
		original := len(options.Target)
		targets := common.RemoveDuplicateURLs(options.Target)
		logger.Info("原始目标数量：%v个，重复目标数量：%v个，去重后目标数量：%v个",
			original, original-len(targets), len(targets))
		return targets
	}
	if options.TargetsFile == "" {
		return nil
	}
	file, err := os.Open(options.TargetsFile)
	if err != nil {
		logger.Error("读取目标文件失败: %v", err)
		return nil
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	unique := make(map[string]struct{}, 1024)
	totalLines := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		totalLines++
		unique[line] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		logger.Error("扫描目标文件出错: %v", err)
	}
	targets := make([]string, 0, len(unique))
	for t := range unique {
		targets = append(targets, t)
	}
	logger.Info("原始目标数量：%v个，重复目标数量：%v个，去重后目标数量：%v个",
		totalLines, totalLines-len(targets), len(targets))
	return targets
}

// progressDisplay 抽象进度条接口（便于测试 mock）。
type progressDisplay interface {
	Add(int) error
	RenderBlank() error
	Finish() error
}

// progressTracker 异步刷新进度条，避免在热路径写入终端。
type progressTracker struct {
	display       progressDisplay
	refreshTicker *time.Ticker
	refreshStop   chan struct{}
	advanceChan   chan struct{}
	wg            sync.WaitGroup
}

func newProgressTracker(total int) *progressTracker {
	bufferSize := total
	if bufferSize > 256 {
		bufferSize = 256
	}
	if bufferSize < 1 {
		bufferSize = 1
	}
	t := &progressTracker{
		display:       output.CreateProgressBar(total),
		refreshTicker: time.NewTicker(500 * time.Millisecond),
		refreshStop:   make(chan struct{}),
		advanceChan:   make(chan struct{}, bufferSize),
	}
	t.wg.Add(2)
	go t.runRefresh()
	go t.runAdvance()
	return t
}

func (p *progressTracker) runRefresh() {
	defer p.wg.Done()
	for {
		select {
		case <-p.refreshStop:
			p.refreshTicker.Stop()
			return
		case <-p.refreshTicker.C:
			if err := p.display.RenderBlank(); err != nil {
				logger.Debug("刷新进度条出错: %v", err)
			}
		}
	}
}

func (p *progressTracker) runAdvance() {
	defer p.wg.Done()
	for range p.advanceChan {
		if err := p.display.Add(1); err != nil {
			logger.Debug("更新进度条出错: %v", err)
		}
	}
}

func (p *progressTracker) Advance() {
	select {
	case p.advanceChan <- struct{}{}:
	default:
	}
}

func (p *progressTracker) RenderBlank() {
	if err := p.display.RenderBlank(); err != nil {
		logger.Debug("重新显示进度条出错: %v", err)
	}
}

func (p *progressTracker) Close() {
	close(p.advanceChan)
	close(p.refreshStop)
	p.wg.Wait()
	if err := p.display.Finish(); err != nil {
		logger.Debug("完成进度条出错: %v", err)
	}
}

// sendScanResult 将目标扫描结果写入 channel；阻塞直至写入成功，或 ctx 取消时放弃写入。
func sendScanResult(ctx context.Context, ch chan<- scanResult, sr scanResult) {
	select {
	case ch <- sr:
	case <-ctx.Done():
		logger.Debug("扫描已取消，目标 %s 结果未写入汇总", sr.target)
	}
}

type scanResult struct {
	target string
	result *TargetResult
}

func calculateChannelCapacity(workerCount, targetCount int) int {
	caps := workerCount * 2
	if caps < 1 {
		caps = 1
	}
	if caps > targetCount {
		return targetCount
	}
	return caps
}

type scanSummary struct{ matched, unmatched int }

// executeScan 逐条输出并只保留汇总计数，已完成目标不占用常驻结果集合。
func (r *Runner) executeScan(ctx context.Context, targets []string, options *types.CmdOptions) (scanSummary, error) {
	var summary scanSummary
	chanCap := calculateChannelCapacity(r.cfg.URLWorkerCount, len(targets))
	resultChan := make(chan scanResult, chanCap)

	progress := newProgressTracker(len(targets))
	var collectorWG sync.WaitGroup
	collectorWG.Add(1)
	go func() {
		defer collectorWG.Done()
		for data := range resultChan {
			if len(data.result.Matches) > 0 {
				summary.matched++
			} else {
				summary.unmatched++
			}
		}
	}()

	saveResult := func(msg string) {
		fmt.Print("\033[2K\r")
		fmt.Println(msg)
		progress.RenderBlank()
	}

	startTime := time.Now()

	type urlTask struct{ target string }

	var urlWG sync.WaitGroup
	pool, err := NewWorkPoolWithFunc(
		r.cfg.URLWorkerCount,
		func(i interface{}) {
			defer urlWG.Done()
			task, ok := i.(urlTask)
			if !ok {
				logger.Error("无效的URL任务类型")
				return
			}
			tr, err := r.ScanTarget(ctx, task.target)
			if err != nil {
				logger.Error("处理目标 %s 失败: %v", task.target, err)
				tr = &TargetResult{
					URL:     task.target,
					Matches: make([]*FingerMatch, 0),
				}
			}
			emitMatchResults(tr, options, saveResult, r.cfg.OutputFormat)

			// 结果已落盘，释放大对象以降低常驻内存
			for _, m := range tr.Matches {
				m.Request = nil
				m.Response = nil
			}
			tr.LastRequest = nil
			tr.LastResponse = nil

			sendScanResult(ctx, resultChan, scanResult{target: task.target, result: tr})
			progress.Advance()
		},
		r.cfg.URLWorkerCount*5,
		3*time.Minute,
		func(i interface{}) { logger.Error("URL池goroutine异常: %v", i) },
	)
	if err != nil {
		close(resultChan)
		collectorWG.Wait()
		progress.Close()
		return summary, fmt.Errorf("创建URL处理池失败: %w", err)
	}
	defer func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = pool.Release(ctx2)
	}()

	for _, target := range targets {
		if ctx.Err() != nil {
			break
		}
		urlWG.Add(1)
		if err := pool.Invoke(urlTask{target: target}); err != nil {
			urlWG.Done()
			logger.Error("提交目标 %s 到线程池失败: %v", target, err)
		}
	}
	urlWG.Wait()
	close(resultChan)
	collectorWG.Wait()
	progress.Close()

	elapsed := time.Since(startTime)
	itemsPerSecond := float64(len(targets)) / elapsed.Seconds()
	fmt.Printf("\n指纹识别 100%% [==================================================] (%d/%d, %.2f it/s)\n",
		len(targets), len(targets), itemsPerSecond)

	stats := r.pool.Stats()
	logger.Info("规则池统计 - 总任务: %d, 已完成: %d, 失败: %d",
		stats.TotalTasks, stats.CompletedTasks, stats.FailedTasks)
	return summary, ctx.Err()
}

// emitMatchResults 把单条扫描结果推到 output 模块。
func emitMatchResults(tr *TargetResult, options *types.CmdOptions, printResult func(string), outputFormat string) {
	output.HandleMatchResults(&output.TargetResult{
		URL:        tr.URL,
		StatusCode: tr.StatusCode,
		Title:      tr.Title,
		ServerInfo: tr.Server,
		Matches:    convertMatchesForOutput(tr.Matches),
		Wappalyzer: tr.Wappalyzer,
		ICP:        tr.ICP,
		Certs:      tr.Certs,
	}, options.Output, options.SockOutput, printResult, outputFormat, tr.LastResponse)
}

func convertMatchesForOutput(matches []*FingerMatch) []*output.FingerMatch {
	result := make([]*output.FingerMatch, len(matches))
	for i, match := range matches {
		result[i] = &output.FingerMatch{
			Finger:   match.Finger,
			Result:   match.Result,
			Request:  match.Request,
			Response: match.Response,
		}
	}
	return result
}
