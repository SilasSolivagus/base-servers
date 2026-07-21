package delegation

import (
	"net/http"

	"connectrpc.com/connect"
)

// JWKSHandler exposes the delegation signer's public keys at
// /.well-known/jwks.json so resource servers can verify delegation tokens
// issued by this server.
type JWKSHandler struct {
	signer *Signer
}

func NewJWKSHandler(signer *Signer) *JWKSHandler { return &JWKSHandler{signer: signer} }

// Register mounts the JWKS endpoint. It is plain HTTP, not a Connect RPC, so
// opts (Connect interceptors) don't apply here; the param exists only to
// satisfy the server.Registrar interface.
func (h *JWKSHandler) Register(mux *http.ServeMux, opts ...connect.HandlerOption) {
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = w.Write(h.signer.JWKS())
	})
}
