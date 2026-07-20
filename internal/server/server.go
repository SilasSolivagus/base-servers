package server

import (
	"net/http"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/config"
	"github.com/SilasSolivagus/base-servers/internal/principal"
)

func mount(mux *http.ServeMux, principals *principal.Handler) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	if principals != nil {
		principals.Register(mux)
	}
}

func New(cfg config.Config, principals *principal.Handler) *http.Server {
	mux := http.NewServeMux()
	mount(mux, principals)
	return &http.Server{Addr: cfg.HTTPAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
}
