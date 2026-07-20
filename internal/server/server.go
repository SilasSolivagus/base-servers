package server

import (
	"net/http"
	"time"

	"github.com/SilasSolivagus/base-servers/internal/config"
)

// Registrar 是任何能把自己挂到 mux 上的 connect handler。
type Registrar interface {
	Register(mux *http.ServeMux)
}

func mountAll(mux *http.ServeMux, handlers []Registrar) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	for _, h := range handlers {
		if h != nil {
			h.Register(mux)
		}
	}
}

func New(cfg config.Config, handlers ...Registrar) *http.Server {
	mux := http.NewServeMux()
	mountAll(mux, handlers)
	return &http.Server{Addr: cfg.HTTPAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
}
