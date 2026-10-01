package output

import (
	"encoding/json"
	"fmt"
	"github.com/cyberspacesec/gxx/v2/utils/logger"
	"github.com/cyberspacesec/gxx/v2/utils/proto"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// InitSockOutput 初始化socket文件输出
func InitSockOutput(sockPath string) error {
	if sockPath == "" {
		return nil
	}

	if err := CloseSockOutput(); err != nil {
		return err
	}

	// 确保输出目录存在
	dir := filepath.Dir(sockPath)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建socket输出目录失败: %v", err)
		}
	}

	// 删除已存在的socket文件（如果存在）
	_ = os.Remove(sockPath)

	// 创建Unix domain socket监听
	unixListener, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("创建Unix domain socket失败: %v", err)
	}

	// 启动协程接受连接并处理
	go func() {
		for {
			conn, err := unixListener.Accept()
			if err != nil {
				// 如果监听已关闭，退出循环
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				logger.Error("Unix socket接受连接失败: %v", err)
				continue
			}

			// 对每个连接启动一个协程处理
			go handleConnection(conn)
		}
	}()

	// 保存监听器，以便后续关闭
	sockListener = unixListener

	return nil
}

// handleConnection 处理单个socket连接
func handleConnection(conn net.Conn) {
	// 添加到连接集合
	sockConnMutex.Lock()
	sockConnections[conn] = true
	sockConnMutex.Unlock()

	// 函数返回时清理连接
	defer func() {
		sockConnMutex.Lock()
		delete(sockConnections, conn)
		_ = conn.Close()
		sockConnMutex.Unlock()
	}()

	// 保持连接打开
	buffer := make([]byte, 1024)
	for {
		_, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				logger.Debug("Unix socket读取错误: %v", err)
			}
			return
		}
	}
}

// WriteToSock 将结果以JSON格式写入所有socket连接
func WriteToSock(opts *WriteOptions) error {
	if sockListener == nil {
		return nil
	}

	// 收集指纹信息
	fingersCount := len(opts.Fingers)
	fingerIDs := make([]string, 0, fingersCount)
	fingerNames := make([]string, 0, fingersCount)

	for _, f := range opts.Fingers {
		fingerIDs = append(fingerIDs, f.Id)
		fingerNames = append(fingerNames, f.Info.Name)
	}

	// 使用传入的备注或生成默认备注
	remark := opts.Remark
	if remark == "" {
		remark = fmt.Sprintf("发现%d个指纹", fingersCount)
	}

	// 处理服务器信息
	serverInfoStr := ""
	if opts.ServerInfo != nil {
		serverInfoStr = opts.ServerInfo.ServerType
	}

	// 格式化响应头
	headersStr := ""
	if opts.Response != nil && opts.Response.RawHeader != nil {
		headersStr = string(opts.Response.RawHeader)
	} else if opts.RespHeaders != "" {
		headersStr = opts.RespHeaders
	}

	// 构建JSON对象
	jsonOutput := &JSONOutput{
		URL:         opts.Target,
		StatusCode:  opts.StatusCode,
		Title:       opts.Title,
		Server:      serverInfoStr,
		FingerIDs:   fingerIDs,
		FingerNames: fingerNames,
		Headers:     headersStr,
		Wappalyzer:  opts.Wappalyzer,
		MatchResult: opts.FinalResult,
		Remark:      remark,
		ICP:         opts.ICP,
		Certs:       opts.Certs,
	}

	// 序列化为JSON
	jsonData, err := json.Marshal(jsonOutput)
	if err != nil {
		return fmt.Errorf("JSON序列化失败: %v", err)
	}

	// 添加换行符
	jsonData = append(jsonData, '\n')

	// 向所有连接写入数据
	sockConnMutex.Lock()
	for conn := range sockConnections {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(jsonData); err != nil {
			_ = conn.Close()
			delete(sockConnections, conn)
		}
	}
	sockConnMutex.Unlock()

	return nil
}

// WriteResultToSock 将结果写入socket文件
func WriteResultToSock(targetResult *TargetResult, lastResponse *proto.Response) {
	writeOpts := CreateWriteOptions(targetResult, "", "", lastResponse)

	// 写入socket文件
	if err := WriteToSock(writeOpts); err != nil {
		logger.Error("写入socket文件失败: %v", err)
	}
}

// CloseSockOutput 关闭socket输出资源
func CloseSockOutput() error {
	var err error

	// 关闭socket监听器
	if sockListener != nil {
		if closeErr := sockListener.Close(); closeErr != nil {
			err = closeErr
		}

		// 关闭所有连接
		sockConnMutex.Lock()
		for conn := range sockConnections {
			_ = conn.Close()
		}
		sockConnections = make(map[net.Conn]bool)
		sockConnMutex.Unlock()

		sockListener = nil
	}

	return err
}

// Close 关闭所有输出资源（文件和socket）
func Close() error {
	// 关闭文件资源
	fileErr := CloseFileOutput()

	// 关闭socket资源
	sockErr := CloseSockOutput()

	// 返回第一个发生的错误
	if fileErr != nil {
		return fileErr
	}
	return sockErr
}
