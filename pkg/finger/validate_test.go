package finger

import (
	"strings"
	"testing"
)

// findDiagnostic 返回第一个代码与字段都相符的诊断。
func findDiagnostic(diagnostics []Diagnostic, code, field string) *Diagnostic {
	for index := range diagnostics {
		if diagnostics[index].Code == code && diagnostics[index].Field == field {
			return &diagnostics[index]
		}
	}
	return nil
}

func TestValidateAcceptsStandardFormat(t *testing.T) {
	for _, strict := range []bool{false, true} {
		if got := Validate([]byte(productRule), ValidateOptions{Strict: strict}); len(got) != 0 {
			t.Fatalf("标准格式的规则不应有诊断（strict=%v）: %+v", strict, got)
		}
	}
}

// 标准格式的每个字段都有校验：严格模式为 error，非严格模式为 warning，并定位到字段所在行。
func TestValidateProductAndServiceFields(t *testing.T) {
	cases := []struct {
		name, old, new, code, field string
		line                        int
	}{
		{"缺少产品标识", "    id: weaver.e-cology\n", "", CodeInvalidProduct, "info.product.id", 5},
		{"产品标识没有厂商段", "id: weaver.e-cology", "id: e-cology", CodeInvalidProduct, "info.product.id", 6},
		{"产品标识有两个点", "id: weaver.e-cology", "id: weaver.e.cology", CodeInvalidProduct, "info.product.id", 6},
		{"产品标识含大写", "id: weaver.e-cology", "id: Weaver.e-cology", CodeInvalidProduct, "info.product.id", 6},
		{"产品标识过长", "id: weaver.e-cology", "id: weaver." + strings.Repeat("a", 90), CodeInvalidProduct, "info.product.id", 6},
		{"缺少产品名称", "    name: e-cology\n", "", CodeInvalidProduct, "info.product.name", 5},
		{"产品名称过长", "    name: e-cology\n", "    name: " + strings.Repeat("名", 201) + "\n", CodeInvalidProduct, "info.product.name", 7},
		{"缺少分类", "    category: application\n", "", CodeInvalidProduct, "info.product.category", 5},
		{"未知分类", "category: application", "category: portal", CodeInvalidProduct, "info.product.category", 9},
		{"缺少身份", "    identity: product\n", "", CodeInvalidProduct, "info.product.identity", 5},
		{"未知身份", "identity: product", "identity: maybe", CodeInvalidProduct, "info.product.identity", 10},
		{"缺少可信度", "    assurance: verified\n", "", CodeInvalidProduct, "info.product.assurance", 5},
		{"未知可信度", "assurance: verified", "assurance: high", CodeInvalidProduct, "info.product.assurance", 11},
		{"标签不合规", "tags: [oa]", "tags: [oa, Web Server]", CodeInvalidProduct, "info.product.tags.1", 12},
		{"标签重复", "tags: [oa]", "tags: [oa, oa]", CodeInvalidProduct, "info.product.tags.1", 12},
		{"标签过多", "tags: [oa]", "tags: [a1, a2, a3, a4, a5, a6, a7, a8, a9]", CodeInvalidProduct, "info.product.tags", 12},
		{"别名为空", "aliases: [泛微OA, ecology]", "aliases: [泛微OA, '']", CodeInvalidProduct, "info.product.aliases.1", 13},
		{"别名过多", "aliases: [泛微OA, ecology]", "aliases: [" + strings.Repeat("a,", 16) + "b]", CodeInvalidProduct, "info.product.aliases", 13},
		{"CPE 不合规", "    description: 协同办公平台\n", "    description: 协同办公平台\n    cpe: ['cpe:2.3:a:weaver']\n", CodeInvalidProduct, "info.product.cpe.0", 17},
		{"参考链接不合规", "      - https://www.weaver.com.cn/\n", "      - https://www.weaver.com.cn/\n      - ftp://weaver.com.cn/\n", CodeInvalidProduct, "info.product.references.1", 16},
		{"参考链接为占位域名", "https://www.weaver.com.cn/", "https://example.com/", CodeInvalidProduct, "info.product.references.0", 15},
		{"参考链接过多", "      - https://www.weaver.com.cn/\n", strings.Repeat("      - https://www.weaver.com.cn/\n", 17), CodeInvalidProduct, "info.product.references", 14},
		{"verified 没有参考链接", "    references:\n      - https://www.weaver.com.cn/\n", "", CodeInvalidProduct, "info.product.references", 5},
		{"描述过长", "description: 协同办公平台", "description: " + strings.Repeat("长", 501), CodeInvalidProduct, "info.product.description", 16},
		{"产品中的未知键", "    vendor: 泛微网络\n", "    vendorr: 泛微网络\n", CodeUnknownKey, "info.product.vendorr", 8},
		{"缺少服务协议", "    - protocol: ssh\n      transport: tcp\n", "    - transport: tcp\n", CodeInvalidService, "info.services.0.protocol", 18},
		{"传输层协议不合规", "transport: tcp", "transport: sctp", CodeInvalidService, "info.services.0.transport", 19},
		{"缺少端口", "      ports: [22, 2222]\n", "", CodeInvalidService, "info.services.0.ports", 18},
		{"端口超出范围", "ports: [22, 2222]", "ports: [22, 70000]", CodeInvalidService, "info.services.0.ports.1", 20},
		{"服务中的未知键", "ports: [22, 2222]", "ports: [22]\n      port: 22", CodeUnknownKey, "info.services.0.port", 21},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(productRule, tc.old) {
				t.Fatalf("样例中找不到 %q", tc.old)
			}
			content := []byte(strings.Replace(productRule, tc.old, tc.new, 1))
			if _, err := Parse(content, ""); err != nil {
				t.Fatalf("样例应能解析: %v", err)
			}
			for strict, severity := range map[bool]string{false: SeverityWarning, true: SeverityError} {
				found := findDiagnostic(Validate(content, ValidateOptions{Strict: strict}), tc.code, tc.field)
				if found == nil || found.Severity != severity || found.Line != tc.line || found.Message == "" {
					t.Fatalf("strict=%v 期望 %s %s 第 %d 行，得到 %+v（全部 %+v）", strict, tc.code, tc.field, tc.line, found, Validate(content, ValidateOptions{Strict: strict}))
				}
			}
		})
	}
}

// TCP/UDP 规则必须声明服务；附加元数据内部的键不检查。
func TestValidateServicesRequiredForNetworkRules(t *testing.T) {
	tcp := "id: ssh-banner\ninfo:\n  name: ssh\n  metadata:\n    anything: {nested: [1, 2]}\nrules:\n  r0:\n    request:\n      type: tcp\n      host: \"[{{domain}}]:22\"\n    expression: response.raw.bcontains(b\"SSH-\")\nexpression: r0()\n"
	diagnostics := Validate([]byte(tcp), ValidateOptions{Strict: true})
	if found := findDiagnostic(diagnostics, CodeMissingServices, "info.services"); found == nil || found.Severity != SeverityError {
		t.Fatalf("TCP 规则缺少服务声明应报告: %+v", diagnostics)
	}
	if findDiagnostic(diagnostics, CodeUnknownKey, "info.metadata.anything") != nil {
		t.Fatalf("附加元数据内部的键不应检查: %+v", diagnostics)
	}
	declared := strings.Replace(tcp, "  metadata:\n", "  services:\n    - protocol: ssh\n      transport: tcp\n      ports: [22]\n  metadata:\n", 1)
	if found := findDiagnostic(Validate([]byte(declared), ValidateOptions{Strict: true}), CodeMissingServices, "info.services"); found != nil {
		t.Fatalf("声明服务后不应报告: %+v", found)
	}
}
