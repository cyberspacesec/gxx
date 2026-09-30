package logger

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mgutz/ansi"
	"github.com/natefinch/lumberjack"
	"github.com/sirupsen/logrus"
)

type CustomFormatter struct {
	IsColored bool
}

func (f *CustomFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logLevel := strings.ToUpper(entry.Level.String())
	message := entry.Message

	if entry.Data["type"] == "success" {
		logLevel = "SUCCESS"
	}

	if f.IsColored {
		var colorFunc func(string) string
		switch entry.Level {
		case logrus.ErrorLevel:
			colorFunc = ansi.ColorFunc("red")
		case logrus.WarnLevel:
			colorFunc = ansi.ColorFunc("yellow")
		case logrus.DebugLevel:
			colorFunc = ansi.ColorFunc("blue")
		case logrus.InfoLevel:
			colorFunc = func(s string) string { return s }
		default:
			colorFunc = func(s string) string { return s }
		}

		if entry.Data["type"] == "success" {
			colorFunc = ansi.ColorFunc("green")
		}

		logLevel = colorFunc(logLevel)
	}

	logMessage := "[" + timestamp + "] [" + logLevel + "] " + message + "\n"
	return []byte(logMessage), nil
}

type PlainFormatter struct {
	CustomFormatter
}

func (f *PlainFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	coloredMessage, err := f.CustomFormatter.Format(entry)
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	plainMessage := re.ReplaceAll(coloredMessage, []byte(""))

	return plainMessage, nil
}

type Logger struct {
	terminalLogger *logrus.Logger
	fileLogger     *logrus.Logger
}

var (
	once     sync.Once
	instance atomic.Pointer[Logger]

	defaultLogger = &Logger{
		terminalLogger: logrus.New(),
		fileLogger:     silentLogrus(),
	}
)

func InitLogger(logDir string, maxFiles int, logLevel int, noFileLog ...bool) {
	once.Do(func() {
		instance.Store(NewLogger(logDir, maxFiles, logLevel, noFileLog...))
	})
}

func (l *Logger) DebugEnabled() bool {
	return l.terminalLogger.IsLevelEnabled(logrus.DebugLevel) || l.fileLogger.IsLevelEnabled(logrus.DebugLevel)
}

// activeLogger 返回当前生效的全局 logger（已 InitLogger 则为 CLI 实例，否则为内置默认实例）。
func activeLogger() *Logger {
	if l := instance.Load(); l != nil {
		return l
	}
	return defaultLogger
}

// ActiveLogLevel 返回当前全局 logger 的日志级别。
func ActiveLogLevel() logrus.Level {
	return activeLogger().terminalLogger.GetLevel()
}

func NewLogger(logDir string, maxFiles int, logLevel int, noFileLog ...bool) *Logger {
	terminalLogger := logrus.New()
	terminalFormatter := &CustomFormatter{IsColored: true}
	terminalLogger.SetFormatter(terminalFormatter)
	terminalLogger.SetOutput(os.Stdout)

	fileLogger := logrus.New()
	plainFormatter := &PlainFormatter{CustomFormatter: *terminalFormatter}
	fileLogger.SetFormatter(plainFormatter)

	disableFileLog := false
	if len(noFileLog) > 0 && noFileLog[0] {
		disableFileLog = true
	}

	if !disableFileLog {
		if _, err := os.Stat(logDir); os.IsNotExist(err) {
			if err := os.MkdirAll(logDir, 0755); err != nil {
				terminalLogger.Errorf("创建日志目录失败: %v", err)
			}
		}

		logFile := &lumberjack.Logger{
			Filename:   logDir + "/" + time.Now().Format("2006-01-02") + ".log",
			MaxBackups: maxFiles,
			MaxSize:    50,
			MaxAge:     10,
			Compress:   true,
		}
		fileLogger.SetOutput(logFile)
	} else {
		fileLogger.SetOutput(io.Discard)
	}

	var level logrus.Level
	switch logLevel {
	case 1:
		level = logrus.InfoLevel
	case 2:
		level = logrus.ErrorLevel
	case 3:
		level = logrus.WarnLevel
	case 4:
		level = logrus.DebugLevel
	case 5:
		level = logrus.TraceLevel
	default:
		level = logrus.InfoLevel
	}

	terminalLogger.SetLevel(level)
	fileLogger.SetLevel(level)

	return &Logger{
		terminalLogger: terminalLogger,
		fileLogger:     fileLogger,
	}
}

// 所有日志方法：先判断级别，不满足直接 return，避免 fmt.Sprintf 和 variadic slice 分配
// logrus 中 PanicLevel=0 ... TraceLevel=6，值越大级别越低

func Info(format string, args ...interface{})  { activeLogger().Info(format, args...) }
func Error(format string, args ...interface{}) { activeLogger().Error(format, args...) }

func Debug(format string, args ...interface{}) { activeLogger().Debug(format, args...) }
func Success(format string, args ...interface{}) {
	activeLogger().Success(format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
	if l.terminalLogger.GetLevel() < logrus.InfoLevel {
		return
	}
	msg := formatMsg(format, args)
	l.terminalLogger.Info(msg)
	l.fileLogger.Info(msg)
}

func (l *Logger) Error(format string, args ...interface{}) {
	if l.terminalLogger.GetLevel() < logrus.ErrorLevel {
		return
	}
	msg := formatMsg(format, args)
	l.terminalLogger.Error(msg)
	l.fileLogger.Error(msg)
}

func (l *Logger) Warn(format string, args ...interface{}) {
	if l.terminalLogger.GetLevel() < logrus.WarnLevel {
		return
	}
	msg := formatMsg(format, args)
	l.terminalLogger.Warn(msg)
	l.fileLogger.Warn(msg)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.terminalLogger.GetLevel() < logrus.DebugLevel {
		return
	}
	msg := formatMsg(format, args)
	l.terminalLogger.Debug(msg)
	l.fileLogger.Debug(msg)
}

func (l *Logger) Success(format string, args ...interface{}) {
	if l.terminalLogger.GetLevel() < logrus.InfoLevel {
		return
	}
	msg := formatMsg(format, args)
	l.terminalLogger.WithField("type", "success").Info(msg)
	l.fileLogger.WithField("type", "success").Info(msg)
}

// formatMsg 延迟格式化：只有在确认需要输出时才格式化字符串
func formatMsg(format string, args []interface{}) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}

func silentLogrus() *logrus.Logger { l := logrus.New(); l.SetOutput(io.Discard); return l }
