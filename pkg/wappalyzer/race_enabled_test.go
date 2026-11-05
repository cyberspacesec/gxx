//go:build race

package wappalyzer

// raceEnabled 表示当前为 -race 构建。竞态检测只对并发访问有意义，单线程的大规模对拍测试
// 在该模式下会慢 5–10 倍而不增加检测能力，可据此缩减规模。
const raceEnabled = true
