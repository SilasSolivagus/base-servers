package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SilasSolivagus/base-servers/internal/config"
	"github.com/SilasSolivagus/base-servers/internal/delegation"
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

func TestJWKSEndpoint(t *testing.T) {
	signer, err := delegation.NewSigner("test-issuer")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	srv := New(config.Config{HTTPAddr: ":0"}, delegation.NewJWKSHandler(signer))
	ts := httptest.NewServer(srv.Handler)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var body struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(body.Keys) == 0 {
		t.Fatal("expected keys in jwks response")
	}
}
