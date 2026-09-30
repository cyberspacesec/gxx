//go:build bench

// 历史 ants 压测实验，默认不参与 go test；运行：go test -tags=bench ./test/...
package main

import (
	"fmt"
	"math/rand"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/panjf2000/ants/v2"
)

func PrintTest() {
	// 默认任务消费用时，随机0-4秒
	//source := rand.NewSource(time.Now().UnixNano())
	//r := rand.New(source)
	//randomNumber := r.Intn(5) // 生成 0 到 4 的随机整数
	//time.Sleep(time.Duration(randomNumber) * time.Second)
	time.Sleep(0 * time.Second)
}

func RuleWork(workerCount int) {
	var wg sync.WaitGroup
	RulePool, _ := ants.NewPoolWithFunc(workerCount, func(i interface{}) {
		defer wg.Done()
		number := i.(int)
		fmt.Printf("RulePool Processing number: %d\n", number)
		PrintTest()
	},
		ants.WithPreAlloc(true),
		ants.WithExpiryDuration(1*time.Minute),
		ants.WithNonblocking(false),
	)
	defer RulePool.Release()
	for i := 1; i <= 5000; i++ {
		wg.Add(1)

		err := RulePool.Invoke(i)

		if err != nil {
			fmt.Printf("Error invoking task: %v\n", err)
			wg.Done()
			continue
		}

		fmt.Println(fmt.Sprintf("RulePool Runner goroutines：%d", RulePool.Running()))
		fmt.Println(fmt.Sprintf("RulePool Free goroutines：%d", RulePool.Free()))
	}
}

func UrlWork() {
	urlTask := 200
	workerCount := 20
	ruleCount := workerCount * 25

	var wg sync.WaitGroup

	UrlPool, _ := ants.NewPoolWithFunc(workerCount, func(i interface{}) {
		defer wg.Done()
		number := i.(int)
		fmt.Printf("UrlPool Processing number: %d\n", number)
		RuleWork(ruleCount)
	},
		ants.WithPreAlloc(true),
		ants.WithExpiryDuration(1*time.Minute),
		ants.WithNonblocking(false),
	)
	defer UrlPool.Release()
	for i := 1; i <= urlTask; i++ {
		wg.Add(1)

		err := UrlPool.Invoke(i)

		if err != nil {
			fmt.Printf("Error invoking task: %v\n", err)
			wg.Done()
			continue
		}

		fmt.Println(fmt.Sprintf("UrlPool Runner goroutines：%d", UrlPool.Running()))
		fmt.Println(fmt.Sprintf("UrlPool Free goroutines：%d", UrlPool.Free()))
	}
}

func TestAnts(t *testing.T) {
	if os.Getenv("GXX_BENCH") == "" {
		t.Skip("跳过 ants 压测；设置 GXX_BENCH=1 启用")
	}
	UrlWork()
}

// 全局RulePool
var GlobalRulePool *ants.PoolWithFunc

// 规则任务结果结构
type RuleResult struct {
	UrlNumber  int
	RuleNumber int
	Timestamp  int64
	Success    bool
	Data       interface{}
}

// 添加任务监控结构
type TaskMonitor struct {
	sync.Mutex
	results      map[int][]RuleResult // 按URL编号存储结果
	totalTasks   map[int]int          // 每个URL的总任务数
	pendingTasks map[int]int          // 每个URL的待处理任务数
}

// 新建任务监控器
func NewTaskMonitor() *TaskMonitor {
	return &TaskMonitor{
		results:      make(map[int][]RuleResult),
		totalTasks:   make(map[int]int),
		pendingTasks: make(map[int]int),
	}
}

// 初始化URL任务
func (tm *TaskMonitor) InitUrlTask(urlNumber int, taskCount int) {
	tm.Lock()
	defer tm.Unlock()
	tm.results[urlNumber] = make([]RuleResult, 0, taskCount)
	tm.totalTasks[urlNumber] = taskCount
	tm.pendingTasks[urlNumber] = taskCount
}

// 添加结果
func (tm *TaskMonitor) AddResult(result RuleResult) {
	tm.Lock()
	defer tm.Unlock()
	urlNumber := result.UrlNumber

	// 初始化结果集（如果不存在）
	if _, exists := tm.results[urlNumber]; !exists {
		tm.results[urlNumber] = make([]RuleResult, 0, 100)
	}

	// 添加结果
	tm.results[urlNumber] = append(tm.results[urlNumber], result)

	// 更新待处理任务数
	if tm.pendingTasks[urlNumber] > 0 {
		tm.pendingTasks[urlNumber]--
	}

	// 打印进度
	completedTasks := len(tm.results[urlNumber])
	totalTasks := tm.totalTasks[urlNumber]
	if (completedTasks%10 == 0 || tm.pendingTasks[urlNumber] == 0) && totalTasks > 0 {
		// 注释掉进度打印
		// fmt.Printf("URL %d progress: %d/%d completed (%.1f%%)\n",
		// 	urlNumber, completedTasks, totalTasks,
		// 	float64(completedTasks)*100/float64(totalTasks))
	}
}

// 获取URL的所有结果
func (tm *TaskMonitor) GetResults(urlNumber int) []RuleResult {
	tm.Lock()
	defer tm.Unlock()
	if results, exists := tm.results[urlNumber]; exists {
		return results
	}
	return []RuleResult{}
}

// 创建全局任务监控器
var GlobalTaskMonitor = NewTaskMonitor()

// 初始化全局RulePool
func InitGlobalRulePool(workerCount int) {
	var err error
	GlobalRulePool, err = ants.NewPoolWithFunc(workerCount, func(i interface{}) {
		task := i.(map[string]interface{})

		// 检查并获取WaitGroup
		if wg, ok := task["wg"].(*sync.WaitGroup); ok {
			defer wg.Done()
		}

		PrintTest()

		// 生成随机数决定是否处理该任务
		source := rand.NewSource(time.Now().UnixNano())
		r := rand.New(source)
		randomValue := r.Float64() // 生成0-1之间的随机数

		// 生成任务结果
		result := RuleResult{
			UrlNumber:  task["urlNumber"].(int),
			RuleNumber: task["number"].(int),
			Timestamp:  task["timestamp"].(int64),
			Success:    randomValue < 0.8, // 80%的概率成功
			Data:       fmt.Sprintf("Result for URL %d, Rule %d (random: %.2f)", task["urlNumber"].(int), task["number"].(int), randomValue),
		}

		// 根据随机条件决定是否添加结果
		// 只有70%的任务会被添加到结果中
		if randomValue < 0.7 {
			// 直接向全局监控器添加结果
			GlobalTaskMonitor.AddResult(result)
		}
	},
		ants.WithPreAlloc(true),
		ants.WithExpiryDuration(1*time.Minute),
		ants.WithNonblocking(false),
	)
	if err != nil {
		panic(fmt.Sprintf("Failed to create GlobalRulePool: %v", err))
	}
}

// 使用全局RulePool的测试
func TestGlobalRulePool(t *testing.T) {
	if os.Getenv("GXX_BENCH") == "" {
		t.Skip("跳过全局 RulePool 压测；设置 GXX_BENCH=1 启用")
	}
	// 初始化全局RulePool，设置足够大的容量
	ruleWorkerCount := 500
	InitGlobalRulePool(ruleWorkerCount)
	defer GlobalRulePool.Release()

	urlTask := 200
	urlWorkerCount := 20

	var wg sync.WaitGroup

	UrlPool, _ := ants.NewPoolWithFunc(urlWorkerCount, func(i interface{}) {
		defer wg.Done()
		urlNumber := i.(int)
		// 注释掉URL处理开始的打印
		// fmt.Printf("UrlPool Processing number: %d\n", urlNumber)

		// 使用全局RulePool处理子任务
		var ruleWg sync.WaitGroup

		// 要处理的规则数量
		ruleCount := 100

		// 初始化URL任务
		GlobalTaskMonitor.InitUrlTask(urlNumber, ruleCount)

		// 提交规则任务
		for j := 1; j <= ruleCount; j++ {
			ruleWg.Add(1)

			// 构造任务参数
			taskParams := map[string]interface{}{
				"urlNumber": urlNumber,
				"number":    j,
				"timestamp": time.Now().Unix(),
				"wg":        &ruleWg, // 传递WaitGroup指针
			}

			// 重试逻辑，确保任务被提交
			maxRetries := 3
			var err error
			for retry := 0; retry < maxRetries; retry++ {
				err = GlobalRulePool.Invoke(taskParams)
				if err == nil {
					break
				}

				// 注释掉重试错误的打印
				// fmt.Printf("Retry %d: Error invoking rule task: %v\n", retry+1, err)
				time.Sleep(10 * time.Millisecond)
			}

			if err != nil {
				// 注释掉重试失败的打印
				// fmt.Printf("Failed after %d retries: Error invoking rule task: %v\n", maxRetries, err)
				ruleWg.Done()
				continue
			}

			// 每提交20个任务就休眠一小段时间，避免任务提交过快
			if j%20 == 0 {
				time.Sleep(5 * time.Millisecond)
			}
		}

		// 等待该URL的所有规则任务完成
		ruleWg.Wait()

		// 获取此URL的所有结果
		urlResults := GlobalTaskMonitor.GetResults(urlNumber)

		// 按照RuleNumber排序结果
		sort.Slice(urlResults, func(i, j int) bool {
			return urlResults[i].RuleNumber < urlResults[j].RuleNumber
		})

		// 保留结果输出
		fmt.Printf("URL %d completed with %d results\n", urlNumber, len(urlResults))

		// 数据结果汇总
		//if len(urlResults) > 0 {
		//	fmt.Printf("URL %d results summary:\n", urlNumber)
		//	for i, result := range urlResults {
		//		if i < 5 { // 只打印前5个结果作为示例
		//			fmt.Printf("  - Result %d: %v\n", i+1, result.Data)
		//		}
		//	}
		//	if len(urlResults) > 5 {
		//		fmt.Printf("  - ... and %d more results\n", len(urlResults)-5)
		//	}
		//} else {
		//	fmt.Printf("URL %d has no results\n", urlNumber)
		//}
	},
		ants.WithPreAlloc(true),
		ants.WithExpiryDuration(1*time.Minute),
		ants.WithNonblocking(false),
	)
	defer UrlPool.Release()

	for i := 1; i <= urlTask; i++ {
		wg.Add(1)

		err := UrlPool.Invoke(i)

		if err != nil {
			// 注释掉URL任务错误的打印
			// fmt.Printf("Error invoking URL task: %v\n", err)
			wg.Done()
			continue
		}
	}

	// 等待所有URL任务完成
	wg.Wait()
	fmt.Println("All URL tasks completed!")
}
