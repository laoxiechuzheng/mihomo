package outbound

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func TestChimeraQUICModeNeverDialsTCP(t *testing.T) {
	c := newChimeraSelectionHarness("quic")
	c.dialTCPFn = func(context.Context, *C.Metadata) (net.Conn, error) {
		t.Fatal("TCP dialed in QUIC mode")
		return nil, nil
	}
	c.dialQUICFn = successfulChimeraPipeDial(t)
	conn, err := c.dialSelected(context.Background(), testChimeraMetadata())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestChimeraTCPModeNeverDialsQUIC(t *testing.T) {
	c := newChimeraSelectionHarness("tcp")
	c.dialQUICFn = func(context.Context, *C.Metadata) (net.Conn, error) {
		t.Fatal("QUIC dialed in TCP mode")
		return nil, nil
	}
	c.dialTCPFn = successfulChimeraPipeDial(t)
	conn, err := c.dialSelected(context.Background(), testChimeraMetadata())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestChimeraAutoQUICSuccessDoesNotCreateTCP(t *testing.T) {
	c := newChimeraSelectionHarness("auto")
	var tcpCalls atomic.Int32
	c.dialTCPFn = func(context.Context, *C.Metadata) (net.Conn, error) {
		tcpCalls.Add(1)
		return nil, errors.New("unexpected TCP dial")
	}
	c.dialQUICFn = successfulChimeraPipeDial(t)
	conn, err := c.dialSelected(context.Background(), testChimeraMetadata())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if got := tcpCalls.Load(); got != 0 {
		t.Fatalf("TCP calls = %d, want 0", got)
	}
}

func TestChimeraAutoFallsBackAfterConfiguredTimeout(t *testing.T) {
	c := newChimeraSelectionHarness("auto")
	c.autoQUICTimeout = 20 * time.Millisecond
	c.dialQUICFn = func(ctx context.Context, _ *C.Metadata) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	c.dialTCPFn = successfulChimeraPipeDial(t)
	started := time.Now()
	conn, err := c.dialSelected(context.Background(), testChimeraMetadata())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("fallback took %s", elapsed)
	}
}

func TestChimeraStreamConnAutoClosesProvidedTCPWhenQUICSucceeds(t *testing.T) {
	c := newChimeraSelectionHarness("auto")
	c.dialQUICFn = successfulChimeraPipeDial(t)
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() { serverSide.Close() })
	var closes atomic.Int32
	provided := &closeCountingConn{Conn: clientSide, closes: &closes}
	conn, err := c.StreamConnContext(context.Background(), provided, testChimeraMetadata())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if got := closes.Load(); got != 1 {
		t.Fatalf("provided TCP close count = %d, want 1", got)
	}
}

func TestNewChimeraQUICRequiresPSKAndUsesDefaultTimeout(t *testing.T) {
	option := validChimeraQUICOption()
	option.QuicPSK = ""
	if _, err := NewChimera(option); err == nil {
		t.Fatal("QUIC mode accepted an empty quic-psk")
	}
	option = validChimeraQUICOption()
	c, err := NewChimera(option)
	if err != nil {
		t.Fatal(err)
	}
	if c.autoQUICTimeout != 1200*time.Millisecond {
		t.Fatalf("auto QUIC timeout = %s", c.autoQUICTimeout)
	}
	if len(c.quicAuthKey) != 32 {
		t.Fatalf("QUIC auth key len = %d", len(c.quicAuthKey))
	}
}

func TestNewChimeraRejectsInvalidAutoQUICTimeout(t *testing.T) {
	option := validChimeraQUICOption()
	option.AutoQUICTimeout = -1
	if _, err := NewChimera(option); err == nil {
		t.Fatal("negative auto-quic-timeout accepted")
	}
}

func TestNewChimeraDoesNotAdvertiseUnsupportedUDP(t *testing.T) {
	option := validChimeraQUICOption()
	option.UDP = true
	c, err := NewChimera(option)
	if err != nil {
		t.Fatal(err)
	}
	if c.SupportUDP() {
		t.Fatal("Chimera advertised UDP support without UDP ASSOCIATE implementation")
	}
}

func newChimeraSelectionHarness(mode string) *Chimera {
	return &Chimera{quicMode: mode, autoQUICTimeout: 20 * time.Millisecond}
}

func successfulChimeraPipeDial(t *testing.T) chimeraDialFunc {
	t.Helper()
	return func(context.Context, *C.Metadata) (net.Conn, error) {
		clientSide, serverSide := net.Pipe()
		t.Cleanup(func() {
			clientSide.Close()
			serverSide.Close()
		})
		return clientSide, nil
	}
}

func testChimeraMetadata() *C.Metadata {
	return &C.Metadata{Host: "example.com", DstPort: 443}
}

func validChimeraQUICOption() ChimeraOption {
	return ChimeraOption{
		Name:            "chimera-test",
		Server:          "127.0.0.1",
		Port:            9443,
		SNI:             "proxy.example",
		ShortID:         "0102030405060708",
		PublicKey:       base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		Fingerprint:     "chrome",
		Mode:            "quic",
		QuicFingerprint: strings.Repeat("a", 64),
		QuicPSK:         base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
}

type closeCountingConn struct {
	net.Conn
	closes *atomic.Int32
}

func (c *closeCountingConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}
