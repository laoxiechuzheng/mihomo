package outbound

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/chimera"
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

func TestNewChimeraAdvertisesUDPOnlyForDatagramModes(t *testing.T) {
	option := validChimeraQUICOption()
	c, err := NewChimera(option)
	if err != nil {
		t.Fatal(err)
	}
	if !c.SupportUDP() {
		t.Fatal("Chimera did not advertise UDP support in QUIC mode")
	}
	option.Mode = "tcp"
	option.QuicPSK = ""
	option.QuicFingerprint = ""
	c, err = NewChimera(option)
	if err != nil {
		t.Fatal(err)
	}
	if c.SupportUDP() {
		t.Fatal("Chimera advertised UDP support in TCP mode")
	}
}

func TestNewChimeraHonorsExplicitUDPDisable(t *testing.T) {
	disabled := false
	option := validChimeraQUICOption()
	option.UDP = &disabled
	c, err := NewChimera(option)
	if err != nil {
		t.Fatal(err)
	}
	if c.SupportUDP() {
		t.Fatal("Chimera advertised UDP after explicit udp: false")
	}
}

func TestChimeraListenPacketHonorsExplicitUDPDisable(t *testing.T) {
	c := newChimeraSelectionHarness("quic")
	c.option = &ChimeraOption{}
	c.Base = NewBase(BaseOption{Name: "test", Addr: "127.0.0.1:9443", Type: C.Chimera, UDP: false})
	c.listenPacketQUICFn = func(context.Context, *C.Metadata) (net.PacketConn, error) {
		t.Fatal("QUIC UDP session opened despite udp: false")
		return nil, nil
	}
	if _, err := c.ListenPacketContext(context.Background(), testChimeraMetadata()); err == nil {
		t.Fatal("udp: false accepted a UDP association")
	}
}

func TestChimeraListenPacketTCPModeRejectsUDP(t *testing.T) {
	c := newChimeraSelectionHarness("tcp")
	c.option = &ChimeraOption{}
	c.Base = NewBase(BaseOption{Name: "test", Addr: "127.0.0.1:9443", Type: C.Chimera})
	if _, err := c.ListenPacketContext(context.Background(), testChimeraMetadata()); err == nil {
		t.Fatal("TCP mode accepted UDP")
	}
}

func TestChimeraListenPacketQuicModeUsesQUIC(t *testing.T) {
	c := newChimeraSelectionHarness("quic")
	c.option = &ChimeraOption{}
	c.Base = NewBase(BaseOption{Name: "test", Addr: "127.0.0.1:9443", Type: C.Chimera, UDP: true})
	var calls atomic.Int32
	c.listenPacketQUICFn = func(context.Context, *C.Metadata) (net.PacketConn, error) {
		calls.Add(1)
		return newTestPacketConn(), nil
	}
	pc, err := c.ListenPacketContext(context.Background(), testChimeraMetadata())
	if err != nil {
		t.Fatal(err)
	}
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("QUIC packet dials = %d, want 1", got)
	}
}

func TestMetadataToChimeraAddrPrefersHostOverFakeIP(t *testing.T) {
	metadata := &C.Metadata{Host: "example.com", DstIP: netip.MustParseAddr("198.18.0.1"), DstPort: 443}
	addr := metadataToChimeraAddr(metadata)
	if addr.Type != chimera.AtypDomain || addr.Domain != "example.com" {
		t.Fatalf("metadata address = %#v, want domain example.com", addr)
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

type testPacketConn struct {
	closed atomic.Bool
}

func newTestPacketConn() *testPacketConn { return &testPacketConn{} }

func (c *testPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	if c.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	return 0, nil, errors.New("test packet conn has no queued datagrams")
}

func (c *testPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return len(p), nil
}

func (c *testPacketConn) Close() error {
	c.closed.Store(true)
	return nil
}

func (c *testPacketConn) LocalAddr() net.Addr              { return testPacketAddr("local") }
func (c *testPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *testPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testPacketConn) SetWriteDeadline(time.Time) error { return nil }

type testPacketAddr string

func (a testPacketAddr) Network() string { return "udp" }
func (a testPacketAddr) String() string  { return string(a) }

type closeCountingConn struct {
	net.Conn
	closes *atomic.Int32
}

func (c *closeCountingConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}
