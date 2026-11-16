package sdk_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cyberspacesec/gxx/sdk"
)

// builtinEntryCase 描述一个产品入口的响应，以及内置规则库中应当命中的子规则。
type builtinEntryCase struct {
	finger  string // 指纹 ID
	rule    string // 应当命中的子规则
	status  int
	headers [][2]string
	body    string
}

// 内置规则库中匹配入口 30x 响应的子规则：引擎在资产内跟随跳转时，
// 30x 响应本身也必须参与匹配。跳转目标统一返回不含任何特征的页面，
// 因此命中只能来自 30x 响应。
var builtinRedirectCases = []builtinEntryCase{
	{"web-协众oa", "r0", 302, [][2]string{{"Location", "index.php?app=main&func=passport&action=login"}, {"Set-Cookie", "CNOAOASESSID=0f3k2; path=/"}}, ""},
	{"web-宝塔控制面板", "r0", 302, [][2]string{{"Location", "/login"}, {"Set-Cookie", "BT_PANEL_6=3d5f1c; Path=/; HttpOnly"}}, ""},
	{"web-apache-struts", "r0", 302, [][2]string{{"Location", "/index.action"}}, ""},
	{"web-apache-struts", "r1", 302, [][2]string{{"Location", "/login.action"}}, ""},
	{"web-atlassian-jira", "r0", 302, [][2]string{{"Location", "/secure/SetupMode!default.jspa"}}, ""},
	{"web-深信服数据中心管理系统", "r1", 302, [][2]string{{"Location", "./src/acloglogin.php"}}, ""},
	{"web-ecology泛微e-office", "r0", 302, [][2]string{{"Location", "/login/Login.jsp"}}, `<script>var dynamiCode="";var iSignaturePortal="";</script>`},
	{"web-360新天擎", "r0", 302, [][2]string{{"Location", "/login?refer=%2F"}, {"Set-Cookie", "SKYLARa0aede9e785feabae789c6e03d=k3; path=/"}}, ""},
	{"web-microsoft-exchange", "r0", 302, [][2]string{{"Location", "/owa/"}, {"Server", "Microsoft-IIS/10.0"}, {"X-Powered-By", "ASP.NET"}}, ""},
	{"web-splunk", "r1", 303, [][2]string{{"Location", "/en-US/"}, {"Server", "Splunkd"}, {"Set-Cookie", "ROUTEID=.1; path=/"}}, "<html><head><title>303 See Other</title></head></html>"},
	{"web-ezoffice", "r0", 302, [][2]string{{"Location", "/defaultroot/portal.jsp?access=oa"}}, ""},
	{"web-深信服零信任访问控制系统aTrust", "r2", 302, [][2]string{{"Location", "/portal/"}}, "<html><head><title>aTrust</title></head></html>"},
	{"web-Dify", "r0", 307, [][2]string{{"Location", "/apps"}}, "/apps"},
	{"web-jfrog", "r2", 302, [][2]string{{"Location", "/artifactory/"}}, ""},
	{"web-apache-solr", "r0", 302, [][2]string{{"Location", "/solr/"}}, ""},
	{"web-confluence", "r0", 302, [][2]string{{"Location", "/login.action?os_destination=%2Findex.action&permissionViolation=true"}, {"X-Confluence-Request-Time", "1700000000000"}}, ""},
	{"web-vectr", "r0", 302, [][2]string{{"Location", "/sra-purpletools-webui/app"}}, ""},
	{"web-citrix-xenmobile", "r0", 302, [][2]string{{"Location", "/zdm/login_xdm_uc.jsp"}, {"Citrix-TransactionId", "8f1c2d"}, {"Set-Cookie", "xmscookie=1; Path=/; Secure"}}, ""},
	{"web-citrix-access-gateway", "r0", 302, [][2]string{{"Location", "/vpn/index.html"}}, `<script>var r = "/vpn/resources/{lang}";</script>`},
}

// 规则里用于判断“响应头存在”的子规则：值是任意的，不能要求字面量 "*"。
var builtinHeaderPresenceCases = []builtinEntryCase{
	{"web-kong", "r2", 200, [][2]string{{"X-Kong-Response-Latency", "1"}}, "ok"},
	{"web-spring-framework", "r3", 200, [][2]string{{"X-Application-Context", "application:8080"}}, "ok"},
	{"web-apache-cocoon", "r0", 200, [][2]string{{"X-Cocoon-Version", "2.1.11"}}, "ok"},
	{"web-elastic", "r0", 200, [][2]string{{"kbn-license-sig", "ab12"}}, "<html><head><title>Elastic</title></head></html>"},
	{"web-深信服终端安全管理系统", "r0", 200, [][2]string{{"Etag", `"5f1c-2d"`}}, `<html><head><title>Loading...</title><script>location.href = "./ui/";</script></head></html>`},
}

func TestBuiltinRulesMatchEntryRedirectResponses(t *testing.T) {
	runBuiltinEntryCases(t, builtinRedirectCases)
}

func TestBuiltinRulesMatchHeaderPresence(t *testing.T) {
	runBuiltinEntryCases(t, builtinHeaderPresenceCases)
}

func runBuiltinEntryCases(t *testing.T, cases []builtinEntryCase) {
	e, err := sdk.NewEngine(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	for _, c := range cases {
		t.Run(c.finger+"/"+c.rule, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/" {
					fmt.Fprint(w, "<html><head><title>landing</title></head><body>landing</body></html>")
					return
				}
				for _, h := range c.headers {
					w.Header().Add(h[0], h[1])
				}
				w.WriteHeader(c.status)
				fmt.Fprint(w, c.body)
			}))
			defer srv.Close()
			result, err := e.Scan(context.Background(), srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range result.Matches {
				if m.Info.ID != c.finger || !m.Result {
					continue
				}
				for _, sub := range m.MatchedRules {
					if sub.Key == c.rule && sub.StatusCode == int32(c.status) {
						return
					}
				}
				t.Fatalf("指纹命中，但不是由 %s 在 %d 响应上命中: %+v", c.rule, c.status, m.MatchedRules)
			}
			t.Fatalf("内置指纹 %s 未命中（状态码 %d，跳转链 %+v）", c.finger, result.StatusCode, result.Redirects)
		})
	}
}
