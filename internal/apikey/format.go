package apikey

import (
	"crypto/rand"
	"hash/crc32"
	"strings"
)

const (
	Prefix    = "bsk_"
	keyIDLen  = 16
	secretLen = 32
	crcLen    = 6 // base62(uint32) padded to 6
	alphabet  = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// randBase62 returns n chars from the base62 alphabet using crypto/rand.
// Mild modulo bias is negligible: 32 chars still yields >180 bits.
func randBase62(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}

// crc computes a fixed-width base62 CRC32 over the given payload.
func crc(payload string) string {
	v := crc32.ChecksumIEEE([]byte(payload))
	buf := make([]byte, crcLen)
	for i := crcLen - 1; i >= 0; i-- {
		buf[i] = alphabet[v%uint32(len(alphabet))]
		v /= uint32(len(alphabet))
	}
	return string(buf)
}

// Generate mints a new key. plaintext = bsk_<keyID>_<secret><crc>, returned once.
func Generate() (plaintext, keyID, secret string, err error) {
	keyID, err = randBase62(keyIDLen)
	if err != nil {
		return "", "", "", err
	}
	secret, err = randBase62(secretLen)
	if err != nil {
		return "", "", "", err
	}
	body := Prefix + keyID + "_" + secret
	plaintext = body + crc(body)
	return plaintext, keyID, secret, nil
}

// Parse validates prefix/shape/CRC and returns the keyID + secret. ok=false on any defect.
func Parse(token string) (keyID, secret string, ok bool) {
	if !strings.HasPrefix(token, Prefix) {
		return "", "", false
	}
	rest := token[len(Prefix):]
	us := strings.IndexByte(rest, '_')
	if us != keyIDLen { // keyID is fixed length, exactly one underscore separates it
		return "", "", false
	}
	keyID = rest[:us]
	tail := rest[us+1:] // secret + crc
	if len(tail) != secretLen+crcLen {
		return "", "", false
	}
	secret = tail[:secretLen]
	gotCRC := tail[secretLen:]
	if crc(Prefix+keyID+"_"+secret) != gotCRC {
		return "", "", false
	}
	return keyID, secret, true
}
