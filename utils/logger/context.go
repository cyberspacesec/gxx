package logger

import (
	"context"
	"fmt"
	"log/slog"
)

// Sink 使扫描实例的日志目的地与 CLI 的全局日志配置相互独立。
type Sink interface {
	Debug(string, ...interface{})
	Info(string, ...interface{})
	Warn(string, ...interface{})
	Error(string, ...interface{})
}
type discardSink struct{}

func (discardSink) Debug(string, ...interface{}) {}
func (discardSink) Info(string, ...interface{})  {}
func (discardSink) Warn(string, ...interface{})  {}
func (discardSink) Error(string, ...interface{}) {}
func (discardSink) DebugEnabled() bool           { return false }
func Discard() Sink                              { return discardSink{} }
func Current() Sink                              { return activeLogger() }

type slogSink struct{ logger *slog.Logger }

func (l slogSink) DebugEnabled() bool { return l.logger.Enabled(context.Background(), slog.LevelDebug) }

// IsDebugEnabled 允许热路径在构造日志参数前检查级别。自定义 Sink 未声明
// 级别接口时仍接收 Debug 调用，保持原有日志接入行为。
func IsDebugEnabled(sink Sink) bool {
	if l, ok := sink.(interface{ DebugEnabled() bool }); ok {
		return l.DebugEnabled()
	}
	return true
}

func FromSlog(l *slog.Logger) Sink {
	if l == nil {
		return Discard()
	}
	return slogSink{l}
}
func (l slogSink) log(level slog.Level, format string, args ...interface{}) {
	if l.logger.Enabled(context.Background(), level) {
		l.logger.Log(context.Background(), level, fmt.Sprintf(format, args...))
	}
}
func (l slogSink) Debug(f string, a ...interface{}) { l.log(slog.LevelDebug, f, a...) }
func (l slogSink) Info(f string, a ...interface{})  { l.log(slog.LevelInfo, f, a...) }
func (l slogSink) Warn(f string, a ...interface{})  { l.log(slog.LevelWarn, f, a...) }
func (l slogSink) Error(f string, a ...interface{}) { l.log(slog.LevelError, f, a...) }

type contextKey struct{}

func WithContext(ctx context.Context, sink Sink) context.Context {
	return context.WithValue(ctx, contextKey{}, sink)
}
func FromContext(ctx context.Context) Sink {
	if sink, ok := ctx.Value(contextKey{}).(Sink); ok {
		return sink
	}
	return Current()
}
