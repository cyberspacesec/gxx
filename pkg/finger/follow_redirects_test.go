package finger

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cyberspacesec/gxx/pkg/network"
	"github.com/cyberspacesec/gxx/utils/proto"
	"gopkg.in/yaml.v2"
)

// follow_redirects: true 表示跟随重定向，false 表示不跟随，未声明时默认跟随。
func TestFollowRedirectsFieldControlsRedirectBehavior(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			fmt.Fprint(w, "final-page")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cases := []struct {
		name       string
		field      string
		wantStatus int32
		wantBody   string
	}{
		{"未声明默认跟随", "", 200, "final-page"},
		{"true 跟随", "      follow_redirects: true\n", 200, "final-page"},
		{"false 不跟随", "      follow_redirects: false\n", 302, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			document := "id: t\nrules:\n  r0:\n    request:\n      method: GET\n      path: /start\n" + tc.field + "    expression: 'true'\nexpression: r0()\n"
			var fg Finger
			if err := yaml.Unmarshal([]byte(document), &fg); err != nil {
				t.Fatal(err)
			}
			rule := fg.Rules[0].Value
			client := network.NewHTTPClient()
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			out, err := SendRequest(ctx, client, server.URL, rule.Request, rule, map[string]any{}, network.OptionsRequest{Timeout: 3 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			resp, _ := out["response"].(*proto.Response)
			if resp == nil || resp.Status != tc.wantStatus {
				t.Fatalf("status=%v 期望=%d", resp, tc.wantStatus)
			}
			if tc.wantBody != "" && string(resp.Body) != tc.wantBody {
				t.Fatalf("body=%q 期望=%q", resp.Body, tc.wantBody)
			}
		})
	}
}
