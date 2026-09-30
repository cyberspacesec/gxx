package router_test

import (
	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/handler"
	"github.com/cyberspacesec/gxx/cmd/gxx-ide/internal/router"
	"net/http/httptest"
	"testing"
)

func TestAPIAccess(t *testing.T) {
	r := router.Setup(handler.NewHandlers(), false, "test-token")
	for _, tt := range []struct {
		name, host, origin, token string
		want                      int
	}{{"missing token", "127.0.0.1", "", "", 401}, {"untrusted site", "127.0.0.1", "https://untrusted.example.com", "test-token", 403}, {"DNS rebinding", "evil.example.com", "", "test-token", 403}, {"native GUI", "wails.localhost", "wails://wails.localhost", "test-token", 200}, {"localhost dev", "127.0.0.1", "http://localhost:5173", "test-token", 200}} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://"+tt.host+"/api/v1/library/default", nil)
			req.Header.Set("Origin", tt.origin)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tt.want {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
		})
	}
}
