import socket

# 创建一个Unix域套接字
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

# 连接到指定的.sock文件
socket_path = './123.sock'
try:
    client.connect(socket_path)
    print("Connected to the socket.")

    # 持续接收消息
    buffer = b''
    while True:
        data = client.recv(1024)
        if not data:
            break
        
        buffer += data
        
        # 尝试解码完整的消息
        try:
            message = buffer.decode('utf-8')
            print('Received:', message)
            buffer = b''  # 清空缓冲区
        except UnicodeDecodeError:
            # 如果解码失败，可能是因为接收到了不完整的UTF-8序列
            # 继续接收数据直到能够完整解码
            continue

finally:
    client.close()
