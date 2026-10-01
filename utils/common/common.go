/*
  - Package common
    @Author: zhizhuo
    @IDE：GoLand
    @File: common.go
    @Date: 2025/2/20 下午3:37*
*/
package common

import (
	"bytes"
	rand2 "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/axgle/mahonia"
	"github.com/cyberspacesec/gxx/v2/utils/proto"
	"github.com/spaolacci/murmur3"
	"math/big"
	"math/rand"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// AddressInfo 封装解析结果的结构体
type AddressInfo struct {
	Host     string
	Port     string
	Scheme   string
	Hostname string
	IsLts    bool
}

const (
	HttpType = "http"
	TcpType  = "tcp"
	UdpType  = "udp"
	SslType  = "ssl"
	GoType   = "go"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyz"
const letterNumberBytes = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const lowletterNumberBytes = "0123456789abcdefghijklmnopqrstuvwxyz"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// UA 生成器：使用真实版本号范围 + 正确的平台-浏览器搭配
// Chrome 主版本每 4 周递增，这里取近 8 个稳定版本覆盖约半年窗口
var (
	chromeMajorVersions  = [...]int{128, 129, 130, 131, 132, 133, 134, 135}
	firefoxMajorVersions = [...]int{128, 129, 130, 131, 132, 133, 134}
	safariVersions       = [...]string{"17.4", "17.5", "17.6", "18.0", "18.1", "18.2"}
	androidVersions      = [...]int{12, 13, 14, 15}
	iosVersionPairs      = [...][2]int{{17, 5}, {17, 6}, {17, 7}, {18, 0}, {18, 1}, {18, 2}}
	androidDevices       = [...]string{
		"Pixel 8 Pro", "Pixel 9", "SM-S928B", "SM-S926B", "SM-A556B",
		"SAMSUNG SM-S921B", "23127PN0CC", "V2304A", "2201123C",
	}
)

// RandomUA 返回一个高度真实的随机 User-Agent
// 保证平台-浏览器-版本号的搭配逻辑正确（如 Safari 只出现在 Apple 平台）
func RandomUA() string {
	// 按真实市场份额加权：Chrome ~65%, Firefox ~8%, Edge ~5%, Safari ~18%, Mobile ~4%
	switch r := rand.Intn(100); {
	case r < 40:
		return chromeDesktopUA()
	case r < 52:
		return chromeDesktopMacUA()
	case r < 58:
		return chromeDesktopLinuxUA()
	case r < 66:
		return firefoxDesktopUA()
	case r < 72:
		return edgeDesktopUA()
	case r < 82:
		return safariDesktopUA()
	case r < 88:
		return chromeMobileAndroidUA()
	case r < 94:
		return safariMobileUA()
	default:
		return chromeMobileIOSUA()
	}
}

func randChromeVer() int { return chromeMajorVersions[rand.Intn(len(chromeMajorVersions))] }
func randFFVer() int     { return firefoxMajorVersions[rand.Intn(len(firefoxMajorVersions))] }

func chromeDesktopUA() string {
	v := randChromeVer()
	return fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", v)
}

func chromeDesktopMacUA() string {
	v := randChromeVer()
	return fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", v)
}

func chromeDesktopLinuxUA() string {
	v := randChromeVer()
	return fmt.Sprintf("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", v)
}

func firefoxDesktopUA() string {
	v := randFFVer()
	platforms := [...]string{
		"Windows NT 10.0; Win64; x64",
		"Macintosh; Intel Mac OS X 10.15",
		"X11; Ubuntu; Linux x86_64",
		"X11; Linux x86_64",
	}
	p := platforms[rand.Intn(len(platforms))]
	return fmt.Sprintf("Mozilla/5.0 (%s; rv:%d.0) Gecko/20100101 Firefox/%d.0", p, v, v)
}

func edgeDesktopUA() string {
	v := randChromeVer()
	return fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36 Edg/%d.0.0.0", v, v)
}

func safariDesktopUA() string {
	sv := safariVersions[rand.Intn(len(safariVersions))]
	return fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Safari/605.1.15", sv)
}

func chromeMobileAndroidUA() string {
	v := randChromeVer()
	av := androidVersions[rand.Intn(len(androidVersions))]
	dev := androidDevices[rand.Intn(len(androidDevices))]
	return fmt.Sprintf("Mozilla/5.0 (Linux; Android %d; %s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Mobile Safari/537.36", av, dev, v)
}

func safariMobileUA() string {
	ios := iosVersionPairs[rand.Intn(len(iosVersionPairs))]
	sv := safariVersions[rand.Intn(len(safariVersions))]
	devices := [...]string{"iPhone", "iPad"}
	dev := devices[rand.Intn(len(devices))]
	if dev == "iPad" {
		return fmt.Sprintf("Mozilla/5.0 (%s; CPU OS %d_%d like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Mobile/15E148 Safari/604.1", dev, ios[0], ios[1], sv)
	}
	return fmt.Sprintf("Mozilla/5.0 (%s; CPU iPhone OS %d_%d like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%s Mobile/15E148 Safari/604.1", dev, ios[0], ios[1], sv)
}

func chromeMobileIOSUA() string {
	v := randChromeVer()
	ios := iosVersionPairs[rand.Intn(len(iosVersionPairs))]
	return fmt.Sprintf("Mozilla/5.0 (iPhone; CPU iPhone OS %d_%d like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/%d.0.0.0 Mobile/15E148 Safari/604.1", ios[0], ios[1], v)
}

func ReverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// FromHex 将十六进制字符串转换为普通字符串
func FromHex(data string) string {
	newStr, err := hex.DecodeString(data)
	if err == nil {
		return string(newStr)
	}
	return data
}

// Str2UTF8 字符串转 utf 8
func Str2UTF8(str string) string {
	if len(str) == 0 {
		return ""
	}
	if !utf8.ValidString(str) {
		return mahonia.NewDecoder("gb18030").ConvertString(str)
	}
	return str
}

// Mmh3Hash32 计算 mmh3 hash
func Mmh3Hash32(raw []byte) int32 {
	var h32 = murmur3.New32()
	_, err := h32.Write(raw)
	if err != nil {
		return 0
	}
	return int32(h32.Sum32())
}

// Base64Encode base64 encode
func Base64Encode(braw []byte) []byte {
	bckd := base64.StdEncoding.EncodeToString(braw)
	var buffer bytes.Buffer
	for i := 0; i < len(bckd); i++ {
		ch := bckd[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.Bytes()
}

// RandLetters 随机小写字母
func RandLetters(n int) string {
	return RandFromChoices(n, letterBytes)
}

// RandFromChoices 从choices里面随机获取
func RandFromChoices(n int, choices string) string {
	b := make([]byte, n)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// A rand.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, r.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = r.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(choices) {
			b[i] = choices[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

// RandomString 生成随机字符串
func RandomString(len int) string {
	var container string
	var str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	b := bytes.NewBufferString(str)
	length := b.Len()
	bigInt := big.NewInt(int64(length))
	for i := 0; i < len; i++ {
		randomInt, _ := rand2.Int(rand2.Reader, bigInt)
		container += string(str[randomInt.Int64()])
	}
	return container
}

// DealMultipart 处理multipart的/n问题
func DealMultipart(contentType string, ruleBody string) (result string, err error) {
	re := regexp.MustCompile(`(?m)multipart/form-Data; boundary=(.*)`)
	match := re.FindStringSubmatch(contentType)
	if len(match) != 2 {
		return "", errors.New("no boundary in content-type")
	}
	boundary := "--" + match[1]

	// 处理rule
	multiPartContent := ""
	multiFile := strings.Split(ruleBody, boundary)
	if len(multiFile) == 0 {
		return multiPartContent, errors.New("ruleBody.Body multi content format err")
	}

	for _, singleFile := range multiFile {
		//	文件头和文件响应
		SplitTmp := strings.Split(singleFile, "\n\n")
		if len(SplitTmp) == 2 {
			fileHeader := SplitTmp[0]
			fileBody := SplitTmp[1]
			fileHeader = strings.Replace(fileHeader, "\n", "\r\n", -1)
			multiPartContent += boundary + fileHeader + "\r\n\r\n" + strings.TrimRight(fileBody, "\n") + "\r\n"
		}
	}
	multiPartContent += boundary + "--" + "\r\n"
	return multiPartContent, nil
}

// ParseTarget 处理请求url地址
func ParseTarget(target, path string) string {
	target = strings.TrimRight(target, "/")
	if path == "" {
		return target
	}
	// 否则，直接将整个 path 附加到 target 后面
	return target + path
}

func UrlTypeToString(u *proto.UrlType) string {
	var buf strings.Builder
	if u.Scheme != "" {
		buf.WriteString(u.Scheme)
		buf.WriteByte(':')
	}
	if u.Scheme != "" || u.Host != "" {
		if u.Host != "" || u.Path != "" {
			buf.WriteString("//")
		}
		if h := u.Host; h != "" {
			buf.WriteString(u.Host)
		}
	}
	path := u.Path
	if path != "" && path[0] != '/' && u.Host != "" {
		buf.WriteByte('/')
	}
	if buf.Len() == 0 {
		if i := strings.IndexByte(path, ':'); i > -1 && strings.IndexByte(path[:i], '/') == -1 {
			buf.WriteString("./")
		}
	}
	buf.WriteString(path)

	if u.Query != "" {
		buf.WriteByte('?')
		buf.WriteString(u.Query)
	}
	if u.Fragment != "" {
		buf.WriteByte('#')
		buf.WriteString(u.Fragment)
	}
	return buf.String()
}

func Url2UrlType(u *url.URL) *proto.UrlType {
	return &proto.UrlType{
		Scheme:   u.Scheme,
		Domain:   u.Hostname(),
		Host:     u.Host,
		Port:     u.Port(),
		Path:     u.EscapedPath(),
		Query:    u.RawQuery,
		Fragment: u.Fragment,
	}
}

func ParseUrl(u *url.URL) *proto.UrlType {
	nu := &proto.UrlType{}
	nu.Scheme = u.Scheme
	nu.Domain = u.Hostname()
	nu.Host = u.Host
	nu.Port = u.Port()
	nu.Path = u.EscapedPath()
	nu.Query = u.RawQuery
	nu.Fragment = u.Fragment
	return nu
}

// ParseAddress 解析地址并返回 AddressInfo
func ParseAddress(address string) (AddressInfo, error) {
	var info AddressInfo

	// 检查是否以 https 或 http 开头
	if strings.HasPrefix(address, "https://") {
		info.Scheme = "https"
		info.IsLts = true // 如果是 https 开头，直接设置 LTS 为 true
	} else if strings.HasPrefix(address, "http://") {
		info.Scheme = "http"
	} else {
		// 如果没有指定协议，默认使用 https
		info.Scheme = "https"
	}

	// 如果地址没有协议部分，补全协议以便解析
	fullURL := address
	if !strings.HasPrefix(address, "http://") && !strings.HasPrefix(address, "https://") {
		fullURL = fmt.Sprintf("%s://%s", info.Scheme, address)
	}

	// 使用 url.Parse 解析地址
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		return info, err
	}

	// 提取主机和端口
	host, port, err := net.SplitHostPort(parsedURL.Host)
	if err != nil {
		// 如果没有显式的端口，使用默认端口
		host = parsedURL.Host
		if info.Scheme == "https" {
			port = "443"
			info.IsLts = true // https 默认端口 443，设置 LTS 为 true
		} else if info.Scheme == "http" {
			port = "80"
		}
	} else {
		// 如果显式指定了端口，检查是否是默认的 TLS 端口
		if info.Scheme == "https" && port == "443" {
			info.IsLts = true
		}
	}

	info.Host = host
	info.Port = port
	info.Hostname = parsedURL.Hostname()

	return info, nil
}

// GetRandomIP 获取随机ip地址
func GetRandomIP() string {
	rand.Seed(time.Now().UnixNano())
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, rand.Uint32())
	return ip.String()
}

// RemoveDuplicateURLs 去除重复的URL
func RemoveDuplicateURLs(urls []string) []string {
	// 使用map来判断URL是否重复
	urlMap := make(map[string]bool)
	var result []string

	for _, u := range urls {
		// 规范化URL，移除前后空格
		u = strings.TrimSpace(u)
		// 跳过空URL
		if u == "" {
			continue
		}

		// 如果URL不在map中，添加到结果中
		if !urlMap[u] {
			urlMap[u] = true
			result = append(result, u)
		}
	}

	return result
}

// RemoveTrailingSlash 删除URL中的最后一个/
func RemoveTrailingSlash(url string) string {
	if strings.HasSuffix(url, "/") {
		return strings.TrimSuffix(url, "/")
	}
	return url
}
