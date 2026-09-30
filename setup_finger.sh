#!/bin/bash

# 设置颜色
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}开始创建指纹库目录结构...${NC}"

# 创建主目录
mkdir -p fingerYaml/{cms,framework,language,server,waf}

# 创建示例指纹文件
cat > fingerYaml/demo.yaml << 'EOF'
id: demo-fingerprint
name: Demo Fingerprint
author: zhizhuo
description: 这是一个演示用的指纹识别规则

set:
  - name: randomstr
    value: "{{random_str(10)}}"

rules:
  r0:
    request:
      method: GET
      path: /
      headers:
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
    expression: response.status == 200
  
  r1:
    request:
      method: GET
      path: /favicon.ico
      headers:
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
    expression: response.status == 200 && response.body.bcontains(b'icon')

expression: r0() && r1()
EOF

# 创建CMS示例
cat > fingerYaml/cms/wordpress.yaml << 'EOF'
id: wordpress
name: WordPress
author: zhizhuo
description: WordPress CMS指纹识别

rules:
  r0:
    request:
      method: GET
      path: /
      headers:
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
    expression: response.body.bcontains(b'wp-content') || response.body.bcontains(b'WordPress')
  
  r1:
    request:
      method: GET
      path: /wp-login.php
      headers:
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
    expression: response.status == 200 && response.body.bcontains(b'WordPress')

expression: r0() || r1()
EOF

# 创建框架示例
cat > fingerYaml/framework/spring.yaml << 'EOF'
id: spring-framework
name: Spring Framework
author: zhizhuo
description: Spring Framework指纹识别

rules:
  r0:
    request:
      method: GET
      path: /
      headers:
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
    expression: response.headers["X-Application-Context"] != ""
  
  r1:
    request:
      method: GET
      path: /error
      headers:
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
    expression: response.body.bcontains(b'org.springframework')

expression: r0() || r1()
EOF

echo -e "${GREEN}指纹库目录结构创建完成!${NC}"
echo -e "${YELLOW}目录结构:${NC}"
find fingerYaml -type f | sort

echo -e "\n${GREEN}现在您可以:${NC}"
echo -e "1. 使用 ${YELLOW}make build${NC} 构建项目（不嵌入指纹库）"
echo -e "2. 使用 ${YELLOW}make build-embed${NC} 构建项目（嵌入指纹库）"
echo -e "3. 添加更多指纹到 ${YELLOW}finger/${NC} 目录" 