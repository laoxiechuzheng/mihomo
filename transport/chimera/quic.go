package chimera

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	mquic "github.com/metacubex/quic-go"
	mtls "github.com/metacubex/tls"
)

// QUIC client side of the chimera v2 protocol (h3 camouflage mode).
// Mirrors chimera-core/internal/quicx: ALPN h3, mandatory cert fingerprint
// pinning, per-stream nonce+HMAC auth, dial-confirmation result frame.

const h3ALPN = "h3"

type QuicClient struct {
	conn     *mquic.Conn
	password string
}

func DeriveQUICPassword(shortID []byte, pubKeyB64 string) string {
	mac := hmac.New(sha256.New, []byte("chimera-quic-key-v2"))
	mac.Write(shortID)
	mac.Write([]byte(pubKeyB64))
	return string(mac.Sum(nil))
}

func DialQuic(ctx context.Context, serverAddr, password, certFingerprint string) (*QuicClient, error) {
	if password == "" {
		return nil, errors.New("chimera-quic: empty auth password")
	}
	if certFingerprint == "" {
		return nil, errors.New("chimera-quic: certificate fingerprint required (mode quic/auto)")
	}
	fp, err := hex.DecodeString(certFingerprint)
	if err != nil || len(fp) != 32 {
		return nil, errors.New("chimera-quic: invalid fingerprint")
	}
	tlsConf := &mtls.Config{
		InsecureSkipVerify: true, // pinned by fingerprint below
		NextProtos:         []string{h3ALPN},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("chimera-quic: no certs")
			}
			sum := sha256.Sum256(rawCerts[0])
			if !bytes.Equal(sum[:], fp) {
				return errors.New("chimera-quic: cert fingerprint mismatch")
			}
			return nil
		},
	}
	conn, err := mquic.DialAddrEarly(ctx, serverAddr, tlsConf, &mquic.Config{MaxIdleTimeout: 120 * time.Second})
	if err != nil {
		return nil, err
	}
	return &QuicClient{conn: conn, password: password}, nil
}

func (q *QuicClient) Close() error {
	if q.conn != nil {
		q.conn.CloseWithError(0, "")
	}
	return nil
}

// DialTarget opens a stream, authenticates, and waits for the dial result.
func (q *QuicClient) DialTarget(ctx context.Context, addr *Address) (net.Conn, error) {
	stream, err := q.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := WriteQUICConnect(stream, CmdConnect, q.password, addr); err != nil {
		stream.Close()
		return nil, err
	}
	stream.SetWriteDeadline(time.Time{})

	stream.SetReadDeadline(time.Now().Add(15 * time.Second))
	status, err := ReadQUICResult(stream)
	stream.SetReadDeadline(time.Time{})
	if err != nil {
		stream.Close()
		return nil, err
	}
	if status != QUICStatusOK {
		stream.Close()
		return nil, fmt.Errorf("chimera-quic: server dial failed (status %d)", status)
	}
	return &quicNetConn{Stream: stream}, nil
}

// quicNetConn adapts a QUIC stream to net.Conn.
type quicNetConn struct {
	*mquic.Stream
}

func (c *quicNetConn) LocalAddr() net.Addr  { return dummyAddr{} }
func (c *quicNetConn) RemoteAddr() net.Addr { return dummyAddr{} }

func (c *quicNetConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "chimera-quic" }
func (dummyAddr) String() string  { return "chimera-quic" }
