// 命令 gen 由规则文件的产品声明生成 SDK 的内置产品目录。在 sdk 目录执行 go generate 即可：
//
//	go generate ./sdk
//
// 等价于在 sdk 目录执行 go run ../internal/catalog/gen -rules ../fingerYaml -out catalog.json。
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cyberspacesec/gxx/internal/catalog"
)

func main() {
	rules := flag.String("rules", "../fingerYaml", "规则目录")
	out := flag.String("out", "catalog.json", "输出的产品目录文件")
	flag.Parse()
	data, err := catalog.Generate(os.DirFS(*rules))
	if err != nil {
		fmt.Fprintf(os.Stderr, "生成产品目录失败：%v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "写入 %s 失败：%v\n", *out, err)
		os.Exit(1)
	}
}
