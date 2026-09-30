# 技术栈匹配语义

HTTP 匹配适配器使用 `github.com/projectdiscovery/wappalyzergo v0.2.44` 提供的完整规则数据、模式解析器、版本提取和置信度合并。响应头、Cookie、HTML、scriptSrc 和 meta 的匹配行为参照该版本实现；JS 对象与 DOM 查询不属于该库的 HTTP 响应识别路径。

`requiredLiterals` 中的模式展开必须与上游 `ParsePattern` 一致。它为每条正则提取必要字面量集合；输入至少包含其中一项才可能匹配。或分支只有在每个分支都能提取必要条件时才参与预筛选，含空分支或无法证明的条件时回退到完整正则。依赖升级时须运行全部模式的预筛选保守性检查及完整识别结果对照测试。预筛选只排除不可能命中的规则，候选仍交由上游解析器判定。编译缓存按工作集淘汰不会删除规则。

以下许可适用于参照上游实现的模式展开和 HTTP 语义适配代码：

MIT License

Copyright (c) 2021 ProjectDiscovery, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
