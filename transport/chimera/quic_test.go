package chimera

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mhttp "github.com/metacubex/http"
	mquic "github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	mtls "github.com/metacubex/tls"
)

func TestH3ConnectRelaysTCPEcho(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	serverName := "proxy.example"
	serverAddr, fingerprint := startH3ConnectServer(t, serverName, key)
	echo := startTCPEchoServer(t)
	echoAddr := echo.Addr().(*net.TCPAddr)

	client, err := DialQuic(context.Background(), serverAddr, serverName, key, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := client.DialTarget(context.Background(), &Address{Type: AtypIPv4, IP: echoAddr.IP, Port: uint16(echoAddr.Port)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("chimera-v5-mihomo")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("chimera-v5-mihomo"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "chimera-v5-mihomo" {
		t.Fatalf("echo = %q", got)
	}
}

func TestH3ConnectRejectsWrongAuthKey(t *testing.T) {
	serverName := "proxy.example"
	serverAddr, fingerprint := startH3ConnectServer(t, serverName, bytes.Repeat([]byte{0x42}, 32))
	client, err := DialQuic(context.Background(), serverAddr, serverName, bytes.Repeat([]byte{0x43}, 32), fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.DialTarget(context.Background(), &Address{Type: AtypDomain, Domain: "example.com", Port: 443}); err == nil {
		t.Fatal("wrong authentication key accepted")
	}
}

func TestDialQuicRejectsWrongCertificateFingerprint(t *testing.T) {
	serverName := "proxy.example"
	serverAddr, _ := startH3ConnectServer(t, serverName, bytes.Repeat([]byte{0x42}, 32))
	if _, err := DialQuic(context.Background(), serverAddr, serverName, bytes.Repeat([]byte{0x42}, 32), strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong certificate fingerprint accepted")
	}
}

func TestAuthorityFromAddressBracketsIPv6(t *testing.T) {
	got, err := authorityFromAddress(&Address{Type: AtypIPv6, IP: net.ParseIP("2001:db8::1"), Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if got != "[2001:db8::1]:443" {
		t.Fatalf("authority = %q", got)
	}
}

func TestQuicStreamConnClosesParentExactlyOnce(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	var closes atomic.Int32
	wrapped := newQuicStreamConn(clientSide, func() error {
		closes.Add(1)
		return nil
	})
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatal(err)
	}
	if got := closes.Load(); got != 1 {
		t.Fatalf("parent close count = %d, want 1", got)
	}
}

func startTCPEchoServer(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener
}

func startH3ConnectServer(t *testing.T, serverName string, authKey []byte) (string, string) {
	t.Helper()
	certificate, fingerprint := newTestCertificate(t, serverName)
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := http3.ConfigureTLSConfig(&mtls.Config{
		Certificates: []mtls.Certificate{certificate},
		MinVersion:   mtls.VersionTLS13,
	})
	listener, err := mquic.ListenEarly(packetConn, tlsConfig, &mquic.Config{
		HandshakeIdleTimeout: 2 * time.Second,
		MaxIdleTimeout:       10 * time.Second,
	})
	if err != nil {
		packetConn.Close()
		t.Fatal(err)
	}
	server := &http3.Server{Handler: mhttp.HandlerFunc(func(w mhttp.ResponseWriter, r *mhttp.Request) {
		if r.Method != mhttp.MethodConnect || !validateTestAuthorization(r.Header.Get("Authorization"), r.Method, r.Host, serverName, authKey, time.Now()) {
			mhttp.Error(w, "Not Found", mhttp.StatusNotFound)
			return
		}
		target, err := net.DialTimeout("tcp", r.Host, 2*time.Second)
		if err != nil {
			mhttp.Error(w, "Bad Gateway", mhttp.StatusBadGateway)
			return
		}
		defer target.Close()
		streamer, ok := w.(http3.HTTPStreamer)
		if !ok {
			mhttp.Error(w, "Bad Gateway", mhttp.StatusBadGateway)
			return
		}
		w.WriteHeader(mhttp.StatusOK)
		stream := streamer.HTTPStream()
		relayTestH3Stream(stream, target)
	})}
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
		_ = packetConn.Close()
	})
	go func() { _ = server.ServeListener(listener) }()
	return listener.Addr().String(), fingerprint
}

func newTestCertificate(t *testing.T, serverName string) (mtls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return mtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:])
}

func validateTestAuthorization(header, method, authority, serverName string, key []byte, now time.Time) bool {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return false
	}
	token, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(token) != 1+8+16+sha256.Size || token[0] != 5 {
		return false
	}
	timestamp := int64(binary.BigEndian.Uint64(token[1:9]))
	issuedAt := time.Unix(timestamp, 0)
	if issuedAt.Before(now.Add(-time.Minute)) || issuedAt.After(now.Add(time.Minute)) {
		return false
	}
	nonce := token[9:25]
	providedMAC := token[25:]
	method = strings.ToUpper(strings.TrimSpace(method))
	authority = strings.ToLower(strings.TrimSpace(authority))
	serverName = strings.ToLower(strings.TrimSpace(serverName))
	var canonical bytes.Buffer
	canonical.WriteByte(5)
	var timestampBytes [8]byte
	binary.BigEndian.PutUint64(timestampBytes[:], uint64(timestamp))
	canonical.Write(timestampBytes[:])
	canonical.Write(nonce)
	for _, field := range []string{method, authority, serverName} {
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(field)))
		canonical.Write(size[:])
		canonical.WriteString(field)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(canonical.Bytes())
	return hmac.Equal(mac.Sum(nil), providedMAC)
}

func relayTestH3Stream(stream *http3.Stream, target net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(target, stream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(stream, target)
		done <- struct{}{}
	}()
	<-done
	_ = stream.SetDeadline(time.Now())
	_ = target.SetDeadline(time.Now())
	<-done
	stream.CancelRead(0)
	_ = stream.Close()
}
