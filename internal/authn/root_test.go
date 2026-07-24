package authn

import (
	"net/http"
	"testing"
)

func hdr(v string) http.Header {
	h := http.Header{}
	if v != "" {
		h.Set("X-BS-Root-Token", v)
	}
	return h
}

func TestCheckRoot(t *testing.T) {
	tok := []byte("s3cret-root")
	cases := []struct {
		name                   string
		header                 string
		tok                    []byte
		wantPresent, wantValid bool
	}{
		{"valid", "s3cret-root", tok, true, true},
		{"present-but-wrong", "wrong", tok, true, false},
		{"absent-with-token-set", "", tok, false, false},
		{"absent-no-token-configured", "", nil, false, false},
		// CRITICAL: unset token + empty header must NOT validate (ConstantTimeCompare("","")==1 trap).
		{"empty-header-empty-token", "", []byte{}, false, false},
	}
	for _, c := range cases {
		p, v := CheckRoot(hdr(c.header), c.tok)
		if p != c.wantPresent || v != c.wantValid {
			t.Errorf("%s: got (present=%v,valid=%v), want (%v,%v)", c.name, p, v, c.wantPresent, c.wantValid)
		}
	}
}
