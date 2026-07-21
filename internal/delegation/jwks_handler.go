package delegation

import "net/http"

// JWKSHandler exposes the delegation signer's public keys at
// /.well-known/jwks.json so resource servers can verify delegation tokens
// issued by this server.
type JWKSHandler struct {
	signer *Signer
}

func NewJWKSHandler(signer *Signer) *JWKSHandler { return &JWKSHandler{signer: signer} }

func (h *JWKSHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = w.Write(h.signer.JWKS())
	})
}
