/*
Package sdk 错误定义。

所有 SDK 返回的错误都通过 fmt.Errorf("%w", sentinel) 包装某个 sentinel error，
调用方使用 errors.Is / errors.As 判断错误类型：

	if errors.Is(err, sdk.ErrEngineClosed) {
	    // 处理引擎已关闭场景
	}
*/
package sdk

import "errors"

// Sentinel errors 集中定义，便于调用方做 errors.Is/As 判断。
var (
	// ErrEmptyTarget 目标 URL 为空。
	ErrEmptyTarget = errors.New("sdk: target URL is empty")

	// ErrEngineClosed 引擎已经被 Close()，不能再执行扫描。
	ErrEngineClosed = errors.New("sdk: engine has been closed")

	// ErrEngineNotReady 引擎尚未完成初始化（指纹未加载、规则池未初始化等）。
	ErrEngineNotReady = errors.New("sdk: engine is not ready")

	// ErrFingerNotLoaded 指纹规则尚未加载或加载失败。
	ErrFingerNotLoaded = errors.New("sdk: finger rules not loaded")

	// ErrScanFailed 扫描过程中发生不可恢复错误。
	ErrScanFailed = errors.New("sdk: scan failed")

	// ErrInvalidOption Functional Option 入参非法（如 timeout < 0、cache size <= 0 等）。
	ErrInvalidOption = errors.New("sdk: invalid option")

	// ErrEmptyResult 扫描完成但底层返回空指针，通常意味着目标不可达或被防火墙拦截。
	ErrEmptyResult = errors.New("sdk: empty scan result")

	// ErrLoadFinger 指纹规则加载失败（YAML 文件不存在 / 格式错误等）。
	ErrLoadFinger = errors.New("sdk: load finger rules failed")
)
