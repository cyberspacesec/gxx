package finger

import (
	"strings"
	"testing"
)

func TestIconURLHTMLVariants(t *testing.T) {
	page := "https://example.com/app/login.html"
	for _, tc := range []struct{ name, body, want string }{
		{"属性顺序", `<link href='/assets/favicon.png' rel='icon'>`, "https://example.com/assets/favicon.png"},
		{"大小写与空白", "<LINK\n HREF = \"icon.ico\" REL = 'SHORTCUT ICON'>", "https://example.com/app/icon.ico"},
		{"多值关系", `<link rel='alternate icon shortcut' href='/icon.png'>`, "https://example.com/icon.png"},
		{"文档基址", `<base href='../assets/'><link href='icon.ico' rel='icon'>`, "https://example.com/assets/icon.ico"},
		{"基址位于图标之后", `<link rel='icon' href='icon.ico'><base href='/assets/'>`, "https://example.com/assets/icon.ico"},
		{"首个基址", `<base href='/a/'><base href='/b/'><link rel='icon' href='icon.ico'>`, "https://example.com/a/icon.ico"},
		{"实体与签名参数", `<link rel='icon' href='/icon%2Fblue.ico?token=a%2Bb+z&amp;next=https://cdn.example.com//x#part'>`, "https://example.com/icon%2Fblue.ico?token=a%2Bb+z&next=https://cdn.example.com//x"},
		{"路径连续斜线", `<link rel='icon' href='/assets//icon.ico'>`, "https://example.com/assets//icon.ico"},
		{"协议相对", `<link href='//cdn.example.com/icon.ico' rel='icon'>`, "https://cdn.example.com/icon.ico"},
		{"优先明确图标", `<meta property='og:image' content='/photo.ico'><link rel='icon' href='/favicon.png'>`, "https://example.com/favicon.png"},
		{"ICO优先", `<link rel='icon' href='/first.png'><link rel='icon' href='/second.ico?v=1'>`, "https://example.com/second.ico?v=1"},
		{"同级顺序稳定", `<link rel='icon' href='/first.png'><link rel='icon' href='/second.png'>`, "https://example.com/first.png"},
		{"微软图标", `<meta content='/tile.png' NAME='msapplication-TileImage'>`, "https://example.com/tile.png"},
		{"触屏图标", `<link sizes='180x180' href='/touch.png' rel='apple-touch-icon'>`, "https://example.com/touch.png"},
		{"社交图片后备", `<meta content='/social.png' property='og:image'>`, "https://example.com/social.png"},
		{"长签名地址", `<link rel='icon' href='/icon.ico?token=` + strings.Repeat("a", 16384) + `'>`, "https://example.com/icon.ico?token=" + strings.Repeat("a", 16384)},
		{"截断的内联声明", `<link rel='icon' href='data:image/png;base64,` + strings.Repeat("YWJj", 65536), "https://example.com/favicon.ico"},
		{"忽略清单", `<link rel='manifest' href='/site.webmanifest'>`, "https://example.com/favicon.ico"},
		{"忽略注释脚本", `<!-- <link rel="icon" href="/comment.ico"> --><script>const s='<link rel="icon" href="/script.ico">';</script><link rel='icon' href='/real.png'>`, "https://example.com/real.png"},
		{"忽略无效协议", `<link rel='icon' href='javascript:alert(1)'><link rel='icon' href='/real.png'>`, "https://example.com/real.png"},
		{"Unicode索引", strings.Repeat("İ", 100) + `<link rel="icon" href="/real.png">`, "https://example.com/real.png"},
		{"带引号的结束符", `<link title='a>b' rel='icon' href='/real.png'>`, "https://example.com/real.png"},
		{"无引号属性", `<link href=/real.ico rel=icon>`, "https://example.com/real.ico"},
		{"重复属性", `<link href='/real.ico' href='/later.ico' rel='icon'>`, "https://example.com/real.ico"},
		{"实体歧义", `<link rel='icon' href='/real.ico?x=1&notit=2'>`, "https://example.com/real.ico?x=1&notit=2"},
		{"候选优先级提升", `<meta property='og:image' content='/same.png'><link rel='icon' href='/other.png'><link rel='icon' href='/same.png'>`, "https://example.com/other.png"},
		{"非标准注释结束", `<!-- example --!><link rel='icon' href='/real.png'>`, "https://example.com/real.png"},
		{"模板内伪图标", `<template><link rel='icon' href='/template.ico'></template><link rel='icon' href='/real.png'>`, "https://example.com/real.png"},
		{"文本区伪图标", `<textarea><link rel='icon' href='/text.ico'></textarea><link rel='icon' href='/real.png'>`, "https://example.com/real.png"},
		{"脚本双重转义", `<script><!--<script></script><link rel='icon' href='/fake.ico'>--></script><link rel='icon' href='/real.png'>`, "https://example.com/real.png"},
		{"纯文本元素", `<plaintext><link rel='icon' href='/text.ico'></plaintext><link rel='icon' href='/later.ico'>`, "https://example.com/favicon.ico"},
		{"相似标签名", `<linké rel='icon' href='/fake.ico'><link rel='icon' href='/real.png'>`, "https://example.com/real.png"},
		{"无图标", `<title>页面</title>`, "https://example.com/favicon.ico"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 20; i++ {
				if got := GetIconURL(page, tc.body); got != tc.want {
					t.Fatalf("图标地址: got=%q want=%q", got, tc.want)
				}
			}
		})
	}
}

func TestICPVisibleTextVariants(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"普通文本", "京ICP备12345678号", "京ICP备12345678号"},
		{"嵌套标签", `<a href='https://beian.miit.gov.cn/'><b>京ICP</b><span>备12345678</span>号-2</a>`, "京ICP备12345678号-2"},
		{"数字实体", `<p>&#20140;ICP&#22791;12345678&#21495;</p>`, "京ICP备12345678号"},
		{"十六进制实体", `<p>&#x4eac;&#x49;&#x43;&#x50;&#x5907;12345678&#x53f7;</p>`, "京ICP备12345678号"},
		{"空白分隔", "<p>京 I C P 备&nbsp; 1234 5678 号 - 2</p>", "京ICP备12345678号-2"},
		{"全角字符", "<p>京ＩＣＰ备１２３４５６７８号－２</p>", "京ICP备12345678号-2"},
		{"混合宽度字母", "<p>京IＣP备12345678号</p>", "京ICP备12345678号"},
		{"GB18030全角字母", "<p>\xbe\xa9\xa3\xc9\xa3\xc3\xa3\xd0\xb1\xb8" + "12345678" + "\xba\xc5</p>", "京ICP备12345678号"},
		{"保留大小写", "<p>备案号：京iCp备12345678号</p>", "京iCp备12345678号"},
		{"经营许可证", "<p>沪ICP证123456号</p>", "沪ICP证123456号"},
		{"传统字号", "<p>京ICP備12345678號</p>", "京ICP备12345678号"},
		{"前置网站序号", "<p>粤ICP备12345678-2号</p>", "粤ICP备12345678-2号"},
		{"多重序号", "<p>粤ICP备12345678-2号-3</p>", "粤ICP备12345678-2号-3"},
		{"零宽分隔", "<p>京I\u200bC\ufeffP备12345678号</p>", "京ICP备12345678号"},
		{"字母分隔标签", "<p>京I<b>C</b><span>P</span>备12345678号</p>", "京ICP备12345678号"},
		{"模板中的样例", "<template><p>京ICP备12345678号</p></template>", ""},
		{"脚本双重转义", "<script><!--<script></script>京ICP备00000000号--></script><p>京ICP备12345678号</p>", "京ICP备12345678号"},
		{"官网链接优先", `<p>京ICP备11111111号</p><a HREF = '//BEIAN.MIIT.GOV.CN/'>沪ICP备22222222号</a>`, "沪ICP备22222222号"},
		{"无效候选之后", `<p>ICP号，京ICP备12345678号</p>`, "京ICP备12345678号"},
		{"其他登记号", `<a href='https://beian.miit.gov.cn/'>其他登记号</a>`, ""},
		{"脚本样例", `<script>const example="京ICP备12345678号";</script><p>普通页面</p>`, ""},
		{"注释样例", `<!-- 京ICP备12345678号 -->`, ""},
		{"样式样例", `<style>body:after{content:'京ICP备12345678号'}</style>`, ""},
		{"属性样例", `<div data-example='京ICP备12345678号'>普通页面</div>`, ""},
		{"禁止跨段拼接", `<p>京ICP</p><p>备12345678号</p>`, ""},
		{"非法文件后缀", `<a href='https://beian.miit.gov.cn/'>京ICP备12345678号.js</a>`, ""},
		{"超长号码", "<p>京ICP备" + strings.Repeat("1", 1000) + "号</p>", ""},
		{"虚假官网域名", `<p>沪ICP备22222222号</p><a href='https://beian.miit.gov.cn.evil.example.com/'>京ICP备11111111号</a>`, "沪ICP备22222222号"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, got := range []string{ExtractICPRecord(tc.body), ExtractICPRecordFromBody([]byte(tc.body))} {
				if got != tc.want {
					t.Fatalf("备案号: got=%q want=%q", got, tc.want)
				}
			}
		})
	}
}

func BenchmarkMetadataExtraction(b *testing.B) {
	padding := strings.Repeat("x", 256<<10)
	for name, body := range map[string]string{
		"IconSmall":        `<html><head><link rel="icon" href="/favicon.ico"></head></html>`,
		"IconLarge":        `<html><head><link rel="icon" href="/favicon.ico"></head><body>` + padding + `</body></html>`,
		"IconRich":         `<html><head><link rel="icon" href="/favicon.ico"></head><body>` + strings.Repeat(`<div><span>普通内容</span></div>`, 8000) + `</body></html>`,
		"ICPPlain":         `<p>京ICP备12345678号</p>`,
		"ICPLarge":         `<html><body>` + padding + `<p>京ICP备12345678号</p></body></html>`,
		"ICPEntity":        `<a href="https://beian.miit.gov.cn/">&#20140;ICP&#22791;12345678&#21495;</a>`,
		"ICPWithoutRecord": strings.Repeat(`<div><span>普通正文</span></div>`, 8000),
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			for i := 0; i < b.N; i++ {
				if strings.HasPrefix(name, "Icon") {
					GetIconURL("https://example.com/app/login.html", body)
				} else {
					ExtractICPRecord(body)
				}
			}
		})
	}
}
