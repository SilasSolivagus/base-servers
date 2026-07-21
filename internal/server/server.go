package server

import (
	"context"
	"net/http"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/config"
)

// Registrar 是任何能把自己挂到 mux 上的 connect handler。
type Registrar interface {
	Register(mux *http.ServeMux)
}

// ReadyFunc 报告依赖(DB/Keycloak)是否就绪;nil 视为始终就绪。
type ReadyFunc func(context.Context) error

func mountAll(mux *http.ServeMux, ready ReadyFunc, handlers []Registrar) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if ready != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()
			if err := ready(ctx); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("not ready"))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	for _, h := range handlers {
		if h != nil {
			h.Register(mux)
		}
	}
}

func New(cfg config.Config, ready ReadyFunc, handlers ...Registrar) *http.Server {
	mux := http.NewServeMux()
	mountAll(mux, ready, handlers)
	return &http.Server{Addr: cfg.HTTPAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
}
