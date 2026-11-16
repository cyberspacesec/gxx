package cel_test

import (
	"strings"
	"testing"

	c "github.com/cyberspacesec/gxx/pkg/cel"
	"github.com/cyberspacesec/gxx/utils/proto"
)

// TestCustomFunctions 覆盖全部自定义函数的结果与错误路径；
// 参数越界必须以 CEL 错误返回，不能 panic。
func TestCustomFunctions(t *testing.T) {
	vars := map[string]any{"response": &proto.Response{
		Status:  200,
		Body:    []byte("<html><title>Hello WordPress 6.7</title>中文页面</html>"),
		Headers: map[string]string{"server": "nginx/1.25.3"},
	}}
	cases := []struct {
		expr string
		want any // nil 表示期望返回错误
	}{
		{`"Hello World".icontains("WORLD")`, true},
		{`"Hello".icontains("bye")`, false},
		{`substr("中文字符串", 1, 2)`, "文字"},
		{`substr("abc", 0, 3)`, "abc"},
		{`substr("abc", 3, 0)`, ""},
		{`substr("abc", 1, 3)`, nil},
		{`substr("abc", -1, 1)`, nil},
		{`substr("abc", 1, 9223372036854775807)`, nil},
		{`substr("abc", 9223372036854775807, 9223372036854775807)`, nil},
		{`replaceAll("a-b-c", "-", "+")`, "a+b+c"},
		{`printable("a\u0000b\tc")`, "abc"},
		{`toUintString("123", ">")`, "123"},
		{`toUintString("123", "<")`, "321"},
		{`toUintString("12a", ">")`, nil},
		{`b"abcdef".bstartsWith(b"abc")`, true},
		{`md5("gxx")`, "beeffefc7059e44843b3c35bc776feaf"},
		{`base64("gxx")`, "Z3h4"},
		{`base64(b"gxx")`, "Z3h4"},
		{`base64Decode("Z3h4")`, "gxx"},
		{`base64Decode("!!")`, nil},
		{`urlencode("a b&c")`, "a+b%26c"},
		{`urldecode("a+b%26c")`, "a b&c"},
		{`urldecode("%zz")`, nil},
		{`hexdecode("677878")`, "gxx"},
		{`hexdecode("zz")`, nil},
		{`faviconHash(b"gxx") == faviconHash("gxx")`, true},
		{`randomInt(5, 5)`, nil},
		{`randomInt(5, 1)`, nil},
		{`randomInt(-9223372036854775808, 9223372036854775807)`, nil},
		{`randomInt(7, 8)`, int64(7)},
		{`size(randomLowercase(12)) == 12`, true},
		{`"version 6.7.1".submatch("version (?P<v>[0-9.]+)")["v"]`, nil}, // 接收者是正则，参数是文本
		{`"version (?P<v>[0-9.]+)".submatch("version 6.7.1")["v"]`, "6.7.1"},
		{`response.body.bcontains(b"WordPress")`, true},
		{`response.body.bcontains(b"wordpress")`, false},
		{`response.body.ibcontains(b"WORDPRESS")`, true},
		{`response.body.ibcontains(b"中文")`, true},
		// 文档中的三种 bmatches 写法与成员写法等价。
		{`response.body.bmatches("WordPress [0-9.]+")`, true},
		{`response.body.bmatches(b"WordPress [0-9.]+")`, true},
		{`bmatches("WordPress [0-9.]+", response.body)`, true},
		{`"WordPress [0-9.]+".bmatches(response.body)`, true},
		{`"Joomla".bmatches(response.body)`, false},
		{`"(".bmatches(response.body)`, nil},
		// submatch / bsubmatch / icontains 的全局写法。
		{`submatch("version (?P<v>[0-9.]+)", "version 6.7.1")["v"]`, "6.7.1"},
		{`bsubmatch("WordPress (?<v>[0-9.]+)", response.body)["v"]`, "6.7"},
		{`icontains("Hello World", "WORLD")`, true},
		{`"WordPress (?P<v>[0-9.]+)".bsubmatch(response.body)["v"]`, "6.7"},
		{`response.headers["server"].contains("nginx")`, true},
		{`size(year(0)) == 4 && size(shortyear(0)) == 2 && size(month(0)) == 2 && size(day(0)) == 2`, true},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			lib := c.NewCustomLib()
			out, err := lib.Evaluate(tc.expr, vars)
			if tc.want == nil {
				if err == nil {
					t.Fatalf("期望错误，得到 %v", out)
				}
				return
			}
			if err != nil {
				t.Fatalf("未期望的错误: %v", err)
			}
			if got := out.Value(); got != tc.want {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestRandomIntRange(t *testing.T) {
	lib := c.NewCustomLib()
	for i := 0; i < 200; i++ {
		out, err := lib.Evaluate(`randomInt(10, 13)`, nil)
		if err != nil {
			t.Fatal(err)
		}
		if v := out.Value().(int64); v < 10 || v >= 13 {
			t.Fatalf("randomInt(10, 13) = %d", v)
		}
	}
	out, err := lib.Evaluate(`randomLowercase(16)`, nil)
	if err != nil || strings.ToLower(out.Value().(string)) != out.Value().(string) {
		t.Fatalf("randomLowercase: %v %v", out, err)
	}
}

// response.body 的直接读取不能越过同名的推导变量：内层 response 是 map 时，
// 必须读取 map 的 body，而不是外层 HTTP 响应。
func TestResponseFieldFastPathRespectsShadowing(t *testing.T) {
	vars := map[string]any{"response": &proto.Response{Body: []byte("outer"), RawHeader: []byte("Server: nginx"), Raw: []byte("SSH-2.0")}}
	cases := []struct {
		expr string
		want bool
	}{
		{`response.body.bcontains(b"outer")`, true},
		{`response.body.ibcontains(b"OUTER")`, true},
		{`response.raw_header.ibcontains(b"server: NGINX")`, true},
		{`response.raw.bcontains(b"SSH-")`, true},
		{`[{"body": b"inner"}].exists(response, response.body.bcontains(b"inner"))`, true},
		{`[{"body": b"inner"}].exists(response, response.body.bcontains(b"outer"))`, false},
		{`[{"body": b"INNER"}].all(response, response.body.ibcontains(b"inner")) && response.body.bcontains(b"outer")`, true},
	}
	for _, tc := range cases {
		lib := c.NewCustomLib()
		out, err := lib.Evaluate(tc.expr, vars)
		if err != nil || out.Value() != tc.want {
			t.Errorf("%s = %v, %v; want %v", tc.expr, out, err, tc.want)
		}
	}
	// response 不是 proto.Response 时按原路径求值。
	lib := c.NewCustomLib()
	if _, err := lib.Evaluate(`response.body.bcontains(b"x")`, map[string]any{"response": nil}); err == nil {
		t.Fatal("response 为 nil 时应返回错误")
	}
}
