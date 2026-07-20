package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthz(t *testing.T) {
	mux := http.NewServeMux()
	mount(mux, nil) // principals 可为 nil,仅测健康检查
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", resp.StatusCode)
	}
}
