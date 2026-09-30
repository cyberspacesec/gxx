package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// UDP 使用本机应答服务，不依赖公网网站提供 UDP 协议。
func startUDPEcho(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { _ = conn.Close(); <-done })
	go func() {
		defer close(done)
		data := make([]byte, 2048)
		for {
			n, peer, err := conn.ReadFrom(data)
			if err != nil {
				return
			}
			if _, err := conn.WriteTo(data[:n], peer); err != nil {
				return
			}
		}
	}()
	return conn.LocalAddr().String()
}

func TestUdpNetWork(t *testing.T) {
	if os.Getenv("GXX_INTEGRATION") == "" {
		t.Skip("跳过外网 UDP/SOCKS5 测试；设置 GXX_INTEGRATION=1 启用")
	}
	// 1. 连接到Socks5代理的TCP端口
	proxyAddr := "127.0.0.1:10808" // 替换为代理地址
	tcpConn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal("连接代理失败:", err)
	}
	defer tcpConn.Close()
	if err := tcpConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// 发送版本和方法选择（无认证）
	tcpConn.Write([]byte{0x05, 0x01, 0x00})

	// 读取方法响应
	resp := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, resp); err != nil || resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatal("SOCKS5握手失败:", err)
	}

	// 2. 发送UDP ASSOCIATE请求
	// 请求格式：VER=5, CMD=3, RSV=0, ATYP=1(IPv4), DST.ADDR=0.0.0.0, DST.PORT=0
	req := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := tcpConn.Write(req); err != nil {
		t.Fatal("发送UDP关联请求失败:", err)
	}

	// 读取UDP关联响应
	buf := make([]byte, 256)
	n, err := io.ReadFull(tcpConn, buf[:10]) // 读取前10字节确定长度
	if err != nil {
		t.Fatal("读取响应失败:", err)
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		t.Fatal("UDP关联失败:", buf[1])
	}

	// 解析绑定的地址和端口
	var host string
	switch buf[3] {
	case 0x01: // IPv4
		host = net.IP(buf[4:8]).String()
	case 0x03: // 域名
		host = string(buf[5 : 5+int(buf[4])])
	case 0x04: // IPv6
		host = net.IP(buf[4:20]).String()
	default:
		t.Fatal("不支持的地址类型")
	}
	port := binary.BigEndian.Uint16(buf[n-2 : n])
	proxyUDPAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// 3. 创建UDP连接
	udpConn, err := net.Dial("udp", proxyUDPAddr)
	if err != nil {
		t.Fatal("创建UDP连接失败:", err)
	}
	defer udpConn.Close()
	if err := udpConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// 4. 封装 UDP 数据，由同机代理访问本机应答服务。
	target := startUDPEcho(t)
	targetAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		t.Fatal("解析目标地址失败:", err)
	}

	// 构造Socks5 UDP头部
	header := new(bytes.Buffer)
	header.Write([]byte{0x00, 0x00, 0x00}) // RSV + FRAG
	if ipv4 := targetAddr.IP.To4(); ipv4 != nil {
		header.WriteByte(0x01) // IPv4
		header.Write(ipv4)
	} else if ipv6 := targetAddr.IP.To16(); ipv6 != nil {
		header.WriteByte(0x04) // IPv6
		header.Write(ipv6)
	} else {
		header.WriteByte(0x03) // 域名
		header.WriteByte(byte(len(targetAddr.IP.String())))
		header.WriteString(targetAddr.IP.String())
	}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(targetAddr.Port))
	header.Write(portBytes)

	// 添加实际数据
	data := []byte("Hello over SOCKS5 UDP!")
	packet := append(header.Bytes(), data...)

	// 5. 发送数据
	if _, err := udpConn.Write(packet); err != nil {
		t.Fatal("发送UDP数据失败:", err)
	}
	fmt.Println("UDP数据通过SOCKS5代理发送成功！")
}
