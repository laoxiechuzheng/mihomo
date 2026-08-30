package chimera

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	mhttp "github.com/metacubex/http"
	mquic "github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	mtls "github.com/metacubex/tls"
)

type QuicClient struct {
	conn       *mquic.Conn
	h3         *http3.ClientConn
	authKey    []byte
	serverName string
	closeOnce  sync.Once
	closeErr   error
}

func DialQuic(ctx context.Context, serverAddr, serverName string, authKey []byte, certFingerprint string) (*QuicClient, error) {
	serverAddr = strings.TrimSpace(serverAddr)
	serverName = strings.ToLower(strings.TrimSpace(serverName))
	if serverAddr == "" {
		return nil, errors.New("chimera-h3: server address is required")
	}
	if serverName == "" {
		return nil, errors.New("chimera-h3: server name is required")
	}
	if len(authKey) != h3AuthKeyLen {
		return nil, errors.New("chimera-h3: authentication key must be exactly 32 bytes")
	}
	tlsConfig, err := pinnedTLSConfig(serverName, certFingerprint)
	if err != nil {
		return nil, err
	}
	quicConfig := &mquic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       60 * time.Second,
		KeepAlivePeriod:      20 * time.Second,
		MaxIncomingStreams:   -1,
	}
	conn, err := mquic.DialAddr(ctx, serverAddr, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}
	transport := &http3.Transport{DisableCompression: true}
	return &QuicClient{
		conn:       conn,
		h3:         transport.NewClientConn(conn),
		authKey:    append([]byte(nil), authKey...),
		serverName: serverName,
	}, nil
}

func (q *QuicClient) Close() error {
	if q == nil {
		return nil
	}
	q.closeOnce.Do(func() {
		if q.h3 != nil {
			q.closeErr = q.h3.CloseWithError(0, "client closed")
		} else if q.conn != nil {
			q.closeErr = q.conn.CloseWithError(0, "client closed")
		}
	})
	return q.closeErr
}

func (q *QuicClient) DialTarget(ctx context.Context, addr *Address) (net.Conn, error) {
	authority, err := authorityFromAddress(addr)
	if err != nil {
		return nil, err
	}
	authorization, err := signAuthorization(q.authKey, mhttp.MethodConnect, authority, q.serverName, time.Now(), rand.Reader)
	if err != nil {
		return nil, err
	}
	stream, err := q.h3.OpenRequestStream(ctx)
	if err != nil {
		return nil, err
	}
	cancelStream := func() {
		stream.CancelRead(mquic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(mquic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	}
	request, err := mhttp.NewRequestWithContext(ctx, mhttp.MethodConnect, "https://"+authority, nil)
	if err != nil {
		cancelStream()
		return nil, err
	}
	request.Host = authority
	request.Header.Set("Authorization", authorization)
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	if err := stream.SendRequestHeader(request); err != nil {
		cancelStream()
		return nil, err
	}
	response, err := stream.ReadResponse()
	if err != nil {
		cancelStream()
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.CopyN(io.Discard, response.Body, 4<<10)
		_ = response.Body.Close()
		stream.CancelWrite(mquic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		return nil, fmt.Errorf("chimera-h3: CONNECT rejected with status %d", response.StatusCode)
	}
	streamConn := &h3RequestConn{
		RequestStream: stream,
		local:         q.conn.LocalAddr(),
		remote:        q.conn.RemoteAddr(),
	}
	return newQuicStreamConn(streamConn, q.Close), nil
}

func pinnedTLSConfig(serverName, fingerprint string) (*mtls.Config, error) {
	fingerprintBytes, err := hex.DecodeString(strings.TrimSpace(fingerprint))
	if err != nil || len(fingerprintBytes) != sha256.Size {
		return nil, errors.New("chimera-h3: invalid certificate fingerprint")
	}
	return &mtls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         mtls.VersionTLS13,
		NextProtos:         []string{http3.NextProtoH3},
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("chimera-h3: no server certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			if !bytes.Equal(sum[:], fingerprintBytes) {
				return errors.New("chimera-h3: certificate fingerprint mismatch")
			}
			return nil
		},
	}, nil
}

func authorityFromAddress(addr *Address) (string, error) {
	if addr == nil || addr.Port == 0 {
		return "", errors.New("chimera-h3: invalid target address")
	}
	port := strconv.Itoa(int(addr.Port))
	switch addr.Type {
	case AtypDomain:
		domain := strings.TrimSpace(addr.Domain)
		if domain == "" {
			return "", errors.New("chimera-h3: empty target domain")
		}
		return net.JoinHostPort(domain, port), nil
	case AtypIPv4:
		ip := addr.IP.To4()
		if ip == nil {
			return "", errors.New("chimera-h3: invalid IPv4 target")
		}
		return net.JoinHostPort(ip.String(), port), nil
	case AtypIPv6:
		ip := addr.IP.To16()
		if ip == nil || addr.IP.To4() != nil {
			return "", errors.New("chimera-h3: invalid IPv6 target")
		}
		return net.JoinHostPort(ip.String(), port), nil
	default:
		return "", errors.New("chimera-h3: unsupported target address type")
	}
}

type h3RequestConn struct {
	*http3.RequestStream
	local  net.Addr
	remote net.Addr
}

func (c *h3RequestConn) LocalAddr() net.Addr  { return c.local }
func (c *h3RequestConn) RemoteAddr() net.Addr { return c.remote }

type quicStreamConn struct {
	net.Conn
	closeOwner func() error
	once       sync.Once
	err        error
}

func newQuicStreamConn(conn net.Conn, closeOwner func() error) net.Conn {
	return &quicStreamConn{Conn: conn, closeOwner: closeOwner}
}

func (c *quicStreamConn) Close() error {
	c.once.Do(func() {
		var streamErr, ownerErr error
		if c.Conn != nil {
			streamErr = c.Conn.Close()
		}
		if c.closeOwner != nil {
			ownerErr = c.closeOwner()
		}
		c.err = errors.Join(streamErr, ownerErr)
	})
	return c.err
}
