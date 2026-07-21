package signingkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// Key 是一把签名密钥;Kid 由公钥的 RFC 7638 thumbprint 派生,跨副本一致。
type Key struct {
	Kid  string
	Priv *ecdsa.PrivateKey
}

func GenerateKey() (*Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	kid, err := thumbprintKid(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Key{Kid: kid, Priv: priv}, nil
}

func thumbprintKid(pub *ecdsa.PublicKey) (string, error) {
	tp, err := (&jose.JSONWebKey{Key: pub}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

func MarshalPriv(priv *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(priv)
}

func ParsePriv(der []byte) (*ecdsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA private key")
	}
	return ec, nil
}
