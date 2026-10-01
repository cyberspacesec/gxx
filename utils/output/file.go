package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/cyberspacesec/gxx/v2/utils/logger"
	"github.com/cyberspacesec/gxx/v2/utils/proto"
	"os"
	"path/filepath"
	"strings"
)

// InitOutput 初始化输出文件并启动异步写入器。
// 异步写入器把 URL 工作池的"格式化 + 落盘"动作从同步路径剥离，
// 消除高并发下抢占全局 mu 锁的串行瓶颈。
func InitOutput(outputPath, format string) error {
	if outputPath == "" {
		return nil
	}
	if err := openOutputFile(outputPath, format); err != nil {
		return err
	}
	enableAsyncWriter()
	return nil
}

// WriteHeader 写入输出文件的表头
func WriteHeader(format string) error {
	if headerWritten || outputFile == nil {
		return nil
	}

	if format == "csv" {
		if csvWriter == nil {
			csvWriter = csv.NewWriter(outputFile)
		}

		// 写入扩展的CSV表头
		if err := csvWriter.Write([]string{
			"URL", "状态码", "标题", "服务器信息",
			"Web服务器", "JS框架", "JS库", "Web框架", "编程语言",
			"指纹ID", "指纹名称", "响应头", "匹配结果", "ICP备案号", "证书", "备注",
		}); err != nil {
			return fmt.Errorf("写入CSV表头失败: %v", err)
		}
		csvWriter.Flush()
	} else if format == "json" {
		// JSON格式不需要写表头
	} else {
		// 文本格式表头
		header := fmt.Sprintf("%-40s%-10s%-30s%-20s%-20s%-20s%-20s%-20s%-20s%-30s%-30s%-50s%-15s%-30s%-20s%-20s\n",
			"URL", "状态码", "标题", "服务器信息",
			"Web服务器", "JS框架", "JS库", "Web框架", "编程语言",
			"指纹ID", "指纹名称", "响应头", "匹配结果", "ICP备案号", "证书", "备注")

		// 写入表头和分隔线
		if _, err := outputFile.WriteString(header); err != nil {
			return fmt.Errorf("写入表头失败: %v", err)
		}

		if _, err := outputFile.WriteString(strings.Repeat("-", 300) + "\n"); err != nil {
			return fmt.Errorf("写入分隔线失败: %v", err)
		}
	}

	headerWritten = true
	return nil
}

// openOutputFile 打开或创建输出文件的通用函数
func openOutputFile(output, format string) error {
	// 如果文件已经正确打开，直接返回
	if outputFile != nil && outputFile.Name() == output {
		return nil
	}

	// 关闭现有的文件
	if outputFile != nil {
		if csvWriter != nil {
			csvWriter.Flush()
		}
		_ = outputFile.Close()
		outputFile = nil
		csvWriter = nil
	}

	// 确保输出目录存在
	dir := filepath.Dir(output)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建输出目录失败: %v", err)
		}
	}

	// 检查文件是否存在
	fileExists := false
	if _, err := os.Stat(output); err == nil {
		fileExists = true
	}

	// 创建模式：新文件或覆盖已有文件
	var file *os.File
	var err error

	if format == "csv" && !fileExists {
		// 对于新的CSV文件，先创建文件并写入UTF-8 BOM
		file, err = os.Create(output)
		if err != nil {
			return fmt.Errorf("创建输出文件失败: %v", err)
		}

		// 写入UTF-8 BOM标识 (EF BB BF)
		if _, err := file.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
			file.Close()
			return fmt.Errorf("写入UTF-8 BOM失败: %v", err)
		}
	} else {
		// 非CSV文件或已存在的CSV文件，使用追加模式打开
		file, err = os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("打开输出文件失败: %v", err)
		}
	}

	outputFile = file
	headerWritten = fileExists

	// 初始化CSV写入器
	if format == "csv" {
		csvWriter = csv.NewWriter(file)
	}

	// 如果是新文件，写入表头
	if !fileExists {
		if err := WriteHeader(format); err != nil {
			return err
		}
	}

	return nil
}

// WriteFingerprints 使用结构体选项写入指纹组合结果
func WriteFingerprints(opts *WriteOptions) error {
	// 检查参数有效性
	if opts.Output == "" {
		return nil
	}

	mu.Lock()
	defer mu.Unlock()

	// 确保文件已打开
	if err := openOutputFile(opts.Output, opts.Format); err != nil {
		return err
	}

	// 收集指纹信息并格式化
	fingersCount := len(opts.Fingers)
	fingerIDs := make([]string, 0, fingersCount)
	fingerNames := make([]string, 0, fingersCount)

	for _, f := range opts.Fingers {
		fingerIDs = append(fingerIDs, f.Id)
		fingerNames = append(fingerNames, f.Info.Name)
	}

	fingerIDStr := fmt.Sprintf("[%s]", strings.Join(fingerIDs, "，"))
	fingerNameStr := fmt.Sprintf("[%s]", strings.Join(fingerNames, "，"))

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

	// 格式化响应头为HTTP标准格式
	headersStr := ""
	if opts.Response != nil && opts.Response.RawHeader != nil {
		headersStr = string(opts.Response.RawHeader)
	} else if opts.RespHeaders != "" {
		headersStr = opts.RespHeaders
	}

	// 提取Wappalyzer信息
	webServers := "-"
	jsFrameworks := "-"
	jsLibraries := "-"
	webFrameworks := "-"
	programmingLangs := "-"

	if opts.Wappalyzer != nil {
		webServers = formatStringArray(opts.Wappalyzer.WebServers)
		jsFrameworks = formatStringArray(opts.Wappalyzer.JavaScriptFrameworks)
		jsLibraries = formatStringArray(opts.Wappalyzer.JavaScriptLibraries)
		webFrameworks = formatStringArray(opts.Wappalyzer.WebFrameworks)
		programmingLangs = formatStringArray(opts.Wappalyzer.ProgrammingLanguages)
	}

	// 构建技术栈信息
	var techStackParts []string
	if webServers != "-" {
		techStackParts = append(techStackParts, fmt.Sprintf("Web服务器：%s", webServers))
	}
	if jsFrameworks != "-" {
		techStackParts = append(techStackParts, fmt.Sprintf("JS框架：%s", jsFrameworks))
	}
	if jsLibraries != "-" {
		techStackParts = append(techStackParts, fmt.Sprintf("JS库：%s", jsLibraries))
	}
	if webFrameworks != "-" {
		techStackParts = append(techStackParts, fmt.Sprintf("Web框架：%s", webFrameworks))
	}
	if programmingLangs != "-" {
		techStackParts = append(techStackParts, fmt.Sprintf("编程语言：%s", programmingLangs))
	}

	techStackStr := "-"
	if len(techStackParts) > 0 {
		techStackStr = strings.Join(techStackParts, " | ")
	}

	// 根据不同格式写入结果
	if opts.Format == "json" {
		// 构建JSON对象（追加 ICP/Certs 字段）
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
		jsonData, err := json.MarshalIndent(jsonOutput, "", "")
		if err != nil {
			return fmt.Errorf("JSON序列化失败: %v", err)
		}

		// 写入JSON数据和换行符
		if _, err := outputFile.Write(jsonData); err != nil {
			return fmt.Errorf("写入JSON数据失败: %v", err)
		}
		if _, err := outputFile.Write([]byte("\n")); err != nil {
			return fmt.Errorf("写入换行符失败: %v", err)
		}

	} else if opts.Format == "csv" {
		// 证书文本格式化（多行，以 \n 连接，CSV 中会被转义）
		certText := formatCertsAsText(opts)

		if err := csvWriter.Write([]string{
			opts.Target,
			fmt.Sprintf("%d", opts.StatusCode),
			opts.Title,
			serverInfoStr,
			webServers,
			jsFrameworks,
			jsLibraries,
			webFrameworks,
			programmingLangs,
			fingerIDStr,
			fingerNameStr,
			strings.ReplaceAll(headersStr, "\n", "\\n"), // CSV中换行符需要转义
			fmt.Sprintf("%v", opts.FinalResult),
			strings.TrimSpace(opts.ICP),
			strings.ReplaceAll(certText, "\n", "\\n"),
			remark,
		}); err != nil {
			return fmt.Errorf("写入CSV记录失败: %v", err)
		}
		csvWriter.Flush()
	} else {
		// 使用strings.Builder提高字符串拼接效率
		var sb strings.Builder
		// 预分配合理的缓冲区大小
		sb.Grow(512 + len(headersStr))

		sb.WriteString("URL: ")
		sb.WriteString(opts.Target)
		sb.WriteString("\n状态码: ")
		sb.WriteString(fmt.Sprintf("%d", opts.StatusCode))
		sb.WriteString("\n标题: ")
		sb.WriteString(opts.Title)
		sb.WriteString("\n服务器: ")
		sb.WriteString(serverInfoStr)

		// 技术栈信息单行显示
		sb.WriteString("\n技术栈: ")
		sb.WriteString(techStackStr)

		sb.WriteString("\n指纹ID: ")
		sb.WriteString(fingerIDStr)
		sb.WriteString("\n指纹名称: ")
		sb.WriteString(fingerNameStr)
		sb.WriteString("\n匹配结果: ")
		sb.WriteString(fmt.Sprintf("%v", opts.FinalResult))
		sb.WriteString("\nICP备案号: ")
		if strings.TrimSpace(opts.ICP) != "" {
			sb.WriteString(strings.TrimSpace(opts.ICP))
		} else {
			sb.WriteString("-")
		}
		// 证书信息块（多证书逐行显示）
		sb.WriteString("\n证书:\n")
		certText := formatCertsAsText(opts)
		if strings.TrimSpace(certText) == "" {
			sb.WriteString("-\n")
		} else {
			sb.WriteString(certText)
			if !strings.HasSuffix(certText, "\n") {
				sb.WriteString("\n")
			}
		}
		sb.WriteString("\n备注: ")
		sb.WriteString(remark)
		sb.WriteString("\n响应头:\n")
		sb.WriteString(headersStr)
		sb.WriteString("\n")
		sb.WriteString(strings.Repeat("-", 100))
		sb.WriteString("\n")

		if _, err := outputFile.WriteString(sb.String()); err != nil {
			return fmt.Errorf("写入结果失败: %v", err)
		}
	}

	return nil
}

// formatCertsAsText 将证书数组格式化为可读文本（多行）
func formatCertsAsText(opts *WriteOptions) string {
	if opts == nil || len(opts.Certs) == 0 {
		return ""
	}
	var b strings.Builder
	for i, c := range opts.Certs {
		if c == nil {
			continue
		}
		// 分隔多张证书
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString("Certificate:\n")

		// 有效性
		b.WriteString("  Valid: ")
		if c.Valid {
			b.WriteString("true\n")
		} else {
			b.WriteString("false\n")
		}

		// Subject 结构化字段
		b.WriteString("  Subject:\n")
		if c.Subject.CommonName != "" {
			b.WriteString("    CN: ")
			b.WriteString(c.Subject.CommonName)
			b.WriteString("\n")
		}
		if len(c.Subject.Organization) > 0 {
			b.WriteString("    O: ")
			b.WriteString(strings.Join(c.Subject.Organization, ", "))
			b.WriteString("\n")
		}
		if len(c.Subject.OrganizationalUnit) > 0 {
			b.WriteString("    OU: ")
			b.WriteString(strings.Join(c.Subject.OrganizationalUnit, ", "))
			b.WriteString("\n")
		}
		if len(c.Subject.Country) > 0 {
			b.WriteString("    C: ")
			b.WriteString(strings.Join(c.Subject.Country, ", "))
			b.WriteString("\n")
		}
		if len(c.Subject.Province) > 0 {
			b.WriteString("    ST: ")
			b.WriteString(strings.Join(c.Subject.Province, ", "))
			b.WriteString("\n")
		}
		if len(c.Subject.Locality) > 0 {
			b.WriteString("    L: ")
			b.WriteString(strings.Join(c.Subject.Locality, ", "))
			b.WriteString("\n")
		}
		if len(c.Subject.StreetAddress) > 0 {
			b.WriteString("    Street: ")
			b.WriteString(strings.Join(c.Subject.StreetAddress, ", "))
			b.WriteString("\n")
		}
		if len(c.Subject.PostalCode) > 0 {
			b.WriteString("    PostalCode: ")
			b.WriteString(strings.Join(c.Subject.PostalCode, ", "))
			b.WriteString("\n")
		}
		if c.Subject.SerialNumber != "" {
			b.WriteString("    SerialNumber(DN): ")
			b.WriteString(c.Subject.SerialNumber)
			b.WriteString("\n")
		}

		// Issuer 结构化字段
		b.WriteString("  Issuer:\n")
		if c.Issuer.CommonName != "" {
			b.WriteString("    CN: ")
			b.WriteString(c.Issuer.CommonName)
			b.WriteString("\n")
		}
		if len(c.Issuer.Organization) > 0 {
			b.WriteString("    O: ")
			b.WriteString(strings.Join(c.Issuer.Organization, ", "))
			b.WriteString("\n")
		}
		if len(c.Issuer.OrganizationalUnit) > 0 {
			b.WriteString("    OU: ")
			b.WriteString(strings.Join(c.Issuer.OrganizationalUnit, ", "))
			b.WriteString("\n")
		}
		if len(c.Issuer.Country) > 0 {
			b.WriteString("    C: ")
			b.WriteString(strings.Join(c.Issuer.Country, ", "))
			b.WriteString("\n")
		}
		if len(c.Issuer.Province) > 0 {
			b.WriteString("    ST: ")
			b.WriteString(strings.Join(c.Issuer.Province, ", "))
			b.WriteString("\n")
		}
		if len(c.Issuer.Locality) > 0 {
			b.WriteString("    L: ")
			b.WriteString(strings.Join(c.Issuer.Locality, ", "))
			b.WriteString("\n")
		}
		if len(c.Issuer.StreetAddress) > 0 {
			b.WriteString("    Street: ")
			b.WriteString(strings.Join(c.Issuer.StreetAddress, ", "))
			b.WriteString("\n")
		}
		if len(c.Issuer.PostalCode) > 0 {
			b.WriteString("    PostalCode: ")
			b.WriteString(strings.Join(c.Issuer.PostalCode, ", "))
			b.WriteString("\n")
		}
		if c.Issuer.SerialNumber != "" {
			b.WriteString("    SerialNumber(DN): ")
			b.WriteString(c.Issuer.SerialNumber)
			b.WriteString("\n")
		}

		if c.SerialNumber != "" {
			b.WriteString("  Serial Number: ")
			b.WriteString(c.SerialNumber)
			b.WriteString("\n")
		}
		if c.PublicKeyAlgorithm != "" {
			b.WriteString("  Public Key Algorithm: ")
			b.WriteString(c.PublicKeyAlgorithm)
			b.WriteString("\n")
		}
		if c.PublicKey != "" {
			b.WriteString("  Public Key: ")
			b.WriteString(c.PublicKey)
			b.WriteString("\n")
		}
		if c.SignatureAlgorithm != "" {
			b.WriteString("  Signature Algorithm: ")
			b.WriteString(c.SignatureAlgorithm)
			b.WriteString("\n")
		}
		if c.Version != 0 {
			b.WriteString("  Version: ")
			b.WriteString(fmt.Sprintf("%d", c.Version))
			b.WriteString("\n")
		}
		if c.NotBefore != "" {
			b.WriteString("  Not Before: ")
			b.WriteString(c.NotBefore)
			b.WriteString("\n")
		}
		if c.NotAfter != "" {
			b.WriteString("  Not After: ")
			b.WriteString(c.NotAfter)
			b.WriteString("\n")
		}
		if len(c.OCSPServer) > 0 {
			b.WriteString("  OCSP Server: ")
			b.WriteString(strings.Join(c.OCSPServer, ", "))
			b.WriteString("\n")
		}
		if len(c.DNSNames) > 0 {
			b.WriteString("  DNS Names: ")
			b.WriteString(strings.Join(c.DNSNames, ", "))
			b.WriteString("\n")
		}
		if len(c.EmailAddresses) > 0 {
			b.WriteString("  Email Addresses: ")
			b.WriteString(strings.Join(c.EmailAddresses, ", "))
			b.WriteString("\n")
		}
		if len(c.IPAddresses) > 0 {
			b.WriteString("  IP Addresses: ")
			b.WriteString(strings.Join(c.IPAddresses, ", "))
			b.WriteString("\n")
		}
		if len(c.URIs) > 0 {
			b.WriteString("  URIs: ")
			b.WriteString(strings.Join(c.URIs, ", "))
			b.WriteString("\n")
		}
		if len(c.CRLDistributionPoints) > 0 {
			b.WriteString("  CRL Distribution Points: ")
			b.WriteString(strings.Join(c.CRLDistributionPoints, ", "))
			b.WriteString("\n")
		}
		if len(c.IssuingCertificateURL) > 0 {
			b.WriteString("  Issuing Certificate URL: ")
			b.WriteString(strings.Join(c.IssuingCertificateURL, ", "))
			b.WriteString("\n")
		}
	}
	return b.String()
}

// WriteResultToFile 将结果写入文件。
// 优先走异步队列以解放 URL 工作池；队列满时退回同步写入，保证不丢数据。
func WriteResultToFile(targetResult *TargetResult, outputs, format string, lastResponse *proto.Response) {
	writeOpts := CreateWriteOptions(targetResult, outputs, format, lastResponse)

	if submitAsync(writeOpts) {
		return
	}
	if err := WriteFingerprints(writeOpts); err != nil {
		logger.Error("写入结果文件失败: %v", err)
	}
}

// CloseFileOutput 关闭仅文件输出资源。
// 关闭顺序：先 drain 异步队列 -> 再 Flush CSV writer -> 再关闭文件句柄，
// 保证 writer goroutine 不会写到已关闭的 FD。
func CloseFileOutput() error {
	disableAsyncWriter()

	mu.Lock()
	defer mu.Unlock()

	if outputFile != nil {
		if csvWriter != nil {
			csvWriter.Flush()
		}
		err := outputFile.Close()
		outputFile = nil
		csvWriter = nil
		headerWritten = false
		return err
	}

	return nil
}
