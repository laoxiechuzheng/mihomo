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
	conn            *mquic.Conn
	packetConn      net.PacketConn
	h3              *http3.ClientConn
	authKey         []byte
	serverName      string
	enableDatagrams bool
	udpMaxPacket    int
	closeOnce       sync.Once
	closeErr        error
}

func DialQuic(ctx context.Context, serverAddr, serverName string, authKey []byte, certFingerprint string) (*QuicClient, error) {
	return dialQuic(ctx, serverAddr, serverName, authKey, certFingerprint, false)
}

// DialQuicWithDatagrams opens a direct Chimera QUIC connection with HTTP
// Datagram support. Production Mihomo uses NewQuicClientFromConn with its
// managed dialer; this helper is retained for standalone callers and tests.
func DialQuicWithDatagrams(ctx context.Context, serverAddr, serverName string, authKey []byte, certFingerprint string) (*QuicClient, error) {
	return dialQuic(ctx, serverAddr, serverName, authKey, certFingerprint, true)
}

func dialQuic(ctx context.Context, serverAddr, serverName string, authKey []byte, certFingerprint string, enableDatagrams bool) (*QuicClient, error) {
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
	quicConfig := defaultQuicConfig(enableDatagrams)
	conn, err := mquic.DialAddr(ctx, serverAddr, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}
	client, err := NewQuicClientFromConn(conn, nil, serverName, authKey, enableDatagrams)
	if err != nil {
		_ = conn.CloseWithError(0, "client setup failed")
		return nil, err
	}
	return client, nil
}

// NewQuicClientFromConn creates a Chimera client on top of an already
// established, certificate-pinned QUIC connection. packetConn is the socket
// supplied by the caller's managed dialer and is closed with the client.
func NewQuicClientFromConn(conn *mquic.Conn, packetConn net.PacketConn, serverName string, authKey []byte, enableDatagrams bool) (*QuicClient, error) {
	serverName = strings.ToLower(strings.TrimSpace(serverName))
	if conn == nil {
		return nil, errors.New("chimera-h3: QUIC connection is required")
	}
	if serverName == "" {
		return nil, errors.New("chimera-h3: server name is required")
	}
	if len(authKey) != h3AuthKeyLen {
		return nil, errors.New("chimera-h3: authentication key must be exactly 32 bytes")
	}
	transport := &http3.Transport{DisableCompression: true, EnableDatagrams: enableDatagrams}
	return &QuicClient{
		conn:            conn,
		packetConn:      packetConn,
		h3:              transport.NewClientConn(conn),
		authKey:         append([]byte(nil), authKey...),
		serverName:      serverName,
		enableDatagrams: enableDatagrams,
		udpMaxPacket:    defaultUDPMaxPacketSize,
	}, nil
}

func defaultQuicConfig(enableDatagrams bool) *mquic.Config {
	return &mquic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       60 * time.Second,
		KeepAlivePeriod:      20 * time.Second,
		MaxIncomingStreams:   -1,
		EnableDatagrams:      enableDatagrams,
	}
}

func (q *QuicClient) Close() error {
	if q == nil {
		return nil
	}
	q.closeOnce.Do(func() {
		if q.h3 != nil {
			q.closeErr = q.h3.CloseWithError(0, "client closed")
		}
		if q.conn != nil {
			if err := q.conn.CloseWithError(0, "client closed"); err != nil && q.closeErr == nil {
				q.closeErr = err
			}
		}
		if q.packetConn != nil {
			if err := q.packetConn.Close(); err != nil && q.closeErr == nil {
				q.closeErr = err
			}
		}
	})
	return q.closeErr
}

func (q *QuicClient) DialUDP(ctx context.Context, addr *Address) (*DatagramConn, error) {
	if q == nil || q.h3 == nil || !q.enableDatagrams {
		return nil, errors.New("chimera-h3: HTTP Datagrams are not enabled")
	}
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
	request.Header.Set("Connect-Protocol", "connect-udp")
	request.Header.Set(http3.CapsuleProtocolHeader, "?1")
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
		cancelStream()
		return nil, fmt.Errorf("chimera-h3: UDP CONNECT rejected with status %d", response.StatusCode)
	}
	return newDatagramConn(stream, q.conn.LocalAddr(), q.conn.RemoteAddr(), udpTargetAddr{authority: authority}, q.udpMaxPacket, q.Close), nil
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

// NewPinnedTLSConfig returns the TLS configuration used by the managed
// Mihomo dialer. The caller must use it with the QUIC socket it supplies to
// NewQuicClientFromConn so certificate pinning is enforced during the
// handshake.
func NewPinnedTLSConfig(serverName, fingerprint string) (*mtls.Config, error) {
	return pinnedTLSConfig(serverName, fingerprint)
}

// DefaultQUICConfig returns the conservative QUIC settings used by Chimera.
func DefaultQUICConfig(enableDatagrams bool) *mquic.Config {
	return defaultQuicConfig(enableDatagrams)
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
