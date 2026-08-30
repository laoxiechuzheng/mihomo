package chimera

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	h3AuthVersion  byte = 5
	h3AuthKeyLen        = 32
	h3AuthNonceLen      = 16
	h3AuthScheme        = "Bearer"
)

var h3AuthKeyInfo = []byte("chimera-h3-auth-v1")

func DeriveAuthKey(psk, publicKey, shortID []byte) ([]byte, error) {
	if len(psk) != h3AuthKeyLen {
		return nil, errors.New("chimera-h3: QUIC PSK must be exactly 32 bytes")
	}
	if len(publicKey) != 32 {
		return nil, errors.New("chimera-h3: REALITY public key must be exactly 32 bytes")
	}
	if len(shortID) == 0 || len(shortID) > 8 {
		return nil, errors.New("chimera-h3: short ID must contain 1 to 8 bytes")
	}
	salt := make([]byte, 0, len(publicKey)+len(shortID))
	salt = append(salt, publicKey...)
	salt = append(salt, shortID...)
	reader := hkdf.New(sha256.New, psk, salt, h3AuthKeyInfo)
	key := make([]byte, h3AuthKeyLen)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func signAuthorization(key []byte, method, authority, serverName string, now time.Time, random io.Reader) (string, error) {
	if len(key) != h3AuthKeyLen {
		return "", errors.New("chimera-h3: authentication key must be exactly 32 bytes")
	}
	method, authority, serverName, err := normalizeAuthFields(method, authority, serverName)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, h3AuthNonceLen)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return "", err
	}
	timestamp := now.Unix()
	input, err := canonicalAuthInput(timestamp, nonce, method, authority, serverName)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(input)
	token := make([]byte, 0, 1+8+h3AuthNonceLen+sha256.Size)
	token = append(token, h3AuthVersion)
	var timestampBytes [8]byte
	binary.BigEndian.PutUint64(timestampBytes[:], uint64(timestamp))
	token = append(token, timestampBytes[:]...)
	token = append(token, nonce...)
	token = append(token, mac.Sum(nil)...)
	return h3AuthScheme + " " + base64.RawURLEncoding.EncodeToString(token), nil
}

func normalizeAuthFields(method, authority, serverName string) (string, string, string, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	authority = strings.ToLower(strings.TrimSpace(authority))
	serverName = strings.ToLower(strings.TrimSpace(serverName))
	if method == "" || authority == "" || serverName == "" {
		return "", "", "", errors.New("chimera-h3: method, authority and server name are required")
	}
	if len(method) > 65535 || len(authority) > 65535 || len(serverName) > 65535 {
		return "", "", "", errors.New("chimera-h3: authentication field is too long")
	}
	return method, authority, serverName, nil
}

func canonicalAuthInput(timestamp int64, nonce []byte, method, authority, serverName string) ([]byte, error) {
	if len(nonce) != h3AuthNonceLen {
		return nil, errors.New("chimera-h3: invalid authentication nonce length")
	}
	var buf bytes.Buffer
	buf.Grow(1 + 8 + h3AuthNonceLen + 6 + len(method) + len(authority) + len(serverName))
	buf.WriteByte(h3AuthVersion)
	var timestampBytes [8]byte
	binary.BigEndian.PutUint64(timestampBytes[:], uint64(timestamp))
	buf.Write(timestampBytes[:])
	buf.Write(nonce)
	for _, field := range []string{method, authority, serverName} {
		if len(field) > 65535 {
			return nil, errors.New("chimera-h3: authentication field is too long")
		}
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(field)))
		buf.Write(size[:])
		buf.WriteString(field)
	}
	return buf.Bytes(), nil
}
