package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthz(t *testing.T) {
	mux := http.NewServeMux()
	mountAll(mux, nil) // handlers 可为 nil,仅测健康检查
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

func TestMountRegistersAll(t *testing.T) {
	var called int
	reg := registrarFunc(func(mux *http.ServeMux) { called++ })
	mux := http.NewServeMux()
	mountAll(mux, []Registrar{reg, reg})
	if called != 2 {
		t.Fatalf("expected 2 registrations, got %d", called)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz not ok: %v %v", err, resp)
	}
}

type registrarFunc func(*http.ServeMux)

func (f registrarFunc) Register(mux *http.ServeMux) { f(mux) }
