package chimera

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

func TestDeriveAuthKeyMatchesCoreV05Fixture(t *testing.T) {
	psk := bytes.Repeat([]byte{0x21}, 32)
	publicKey := bytes.Repeat([]byte{0x22}, 32)
	shortID := []byte{1, 2, 3, 4}
	got, err := DeriveAuthKey(psk, publicKey, shortID)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("1e085fd2e38f1162d9022dfb794e20b79797557a3495c96bfbbb26a19ff082c7")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("derived key = %x, want %x", got, want)
	}
}

func TestDeriveAuthKeyRejectsInvalidCredentialLengths(t *testing.T) {
	validPSK := make([]byte, 32)
	validPublicKey := make([]byte, 32)
	for name, tc := range map[string]struct {
		psk       []byte
		publicKey []byte
		shortID   []byte
	}{
		"short psk":        {make([]byte, 31), validPublicKey, []byte{1}},
		"short public key": {validPSK, make([]byte, 31), []byte{1}},
		"empty short id":   {validPSK, validPublicKey, nil},
		"long short id":    {validPSK, validPublicKey, make([]byte, 9)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DeriveAuthKey(tc.psk, tc.publicKey, tc.shortID); err == nil {
				t.Fatal("invalid credentials accepted")
			}
		})
	}
}

func TestSignAuthorizationMatchesCoreV05Fixture(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.NewReader(bytes.Repeat([]byte{0x11}, 16))
	got, err := signAuthorization(key, "connect", "EXAMPLE.COM:443", "Proxy.Example", time.Unix(1_788_000_000, 0), nonce)
	if err != nil {
		t.Fatal(err)
	}
	const want = "Bearer BQAAAABqkrcAEREREREREREREREREREREbG_wh2qF3Mt0HMJGgnPJE93XXTs0DRbwP0SgtH5p9Fg"
	if got != want {
		t.Fatalf("authorization = %q, want %q", got, want)
	}
}

func TestSignAuthorizationRejectsInvalidInput(t *testing.T) {
	validKey := make([]byte, 32)
	validNonce := bytes.NewReader(make([]byte, 16))
	if _, err := signAuthorization(make([]byte, 31), "CONNECT", "example.com:443", "proxy.example", time.Now(), validNonce); err == nil {
		t.Fatal("short auth key accepted")
	}
	if _, err := signAuthorization(validKey, "", "example.com:443", "proxy.example", time.Now(), bytes.NewReader(make([]byte, 16))); err == nil {
		t.Fatal("empty method accepted")
	}
}
