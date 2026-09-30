package output

// output.go 作为主入口文件，引用其他分割后的功能文件

// 本模块主要功能:
// 1. 支持将指纹识别结果以不同格式(CSV/TXT/JSON)输出到文件
// 2. 支持通过Unix domain socket实时输出结果
// 3. 提供灵活的输出选项配置
// 4. 支持控制台彩色输出和进度条显示

// 文件组织:
// - types.go: 数据结构和全局变量定义
// - file.go: 文件输出相关功能
// - sock.go: Socket输出相关功能
// - util.go: 辅助函数和工具方法
// - console.go: 控制台输出和进度条相关功能

// 主要公开接口:
// - InitOutput: 初始化文件输出
// - InitSockOutput: 初始化Socket输出
// - WriteFingerprints: 写入指纹识别结果
// - WriteResultToFile: 将结果写入文件
// - WriteResultToSock: 将结果写入Socket
// - HandleMatchResults: 处理匹配结果并输出
// - CreateProgressBar: 创建进度条
// - Close: 关闭所有输出资源
