// Package signingkey 管理委托签名密钥的生命周期:信封加密、生成、持久化、轮换。
package signingkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

// KEKFromEnv 从 BS_SIGNING_KEK 读取并校验 KEK(base64-std 编码的 32 字节)。
// 未设或长度不对返回错误 —— 上层据此 fail-closed。
func KEKFromEnv() ([]byte, error) {
	v := os.Getenv("BS_SIGNING_KEK")
	if v == "" {
		return nil, fmt.Errorf("BS_SIGNING_KEK is required (base64 of 32 bytes)")
	}
	kek, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("BS_SIGNING_KEK not valid base64: %w", err)
	}
	if len(kek) != 32 {
		return nil, fmt.Errorf("BS_SIGNING_KEK must decode to 32 bytes, got %d", len(kek))
	}
	return kek, nil
}

// Cipher 用 AES-256-GCM 对签名私钥做信封加密;kid 作 AAD 绑定密文与其密钥标识。
type Cipher struct{ aead cipher.AEAD }

func NewCipher(kek []byte) (*Cipher, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("KEK must be 32 bytes, got %d", len(kek))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// Seal 返回 nonce||ciphertext;nonce 为随机 96-bit。
func (c *Cipher) Seal(kid string, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := c.aead.Seal(nil, nonce, plaintext, []byte(kid))
	return append(nonce, ct...), nil
}

// Open 拆出 nonce 并解密;错 KEK 或错 kid(AAD 不符)返回错误。
func (c *Cipher) Open(kid string, blob []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(blob) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return c.aead.Open(nil, blob[:ns], blob[ns:], []byte(kid))
}
