package outbound

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/chimera"
	"github.com/metacubex/mihomo/transport/tuic/common"
)

const defaultChimeraAutoQUICTimeout = 1200 * time.Millisecond

type chimeraDialFunc func(context.Context, *C.Metadata) (net.Conn, error)
type chimeraPacketDialFunc func(context.Context, *C.Metadata) (net.PacketConn, error)

type Chimera struct {
	*Base
	option             *ChimeraOption
	realityConfig      *tlsC.RealityConfig
	clientFingerprint  tlsC.UClientHelloID
	quicMode           string
	quicAuthKey        []byte
	quicFP             string
	autoQUICTimeout    time.Duration
	dialTCPFn          chimeraDialFunc
	dialQUICFn         chimeraDialFunc
	listenPacketQUICFn chimeraPacketDialFunc
}

type ChimeraOption struct {
	BasicOption
	Name            string `proxy:"name"`
	Server          string `proxy:"server"`
	Port            int    `proxy:"port"`
	SNI             string `proxy:"sni"`
	ShortID         string `proxy:"short-id,omitempty"`
	PublicKey       string `proxy:"public-key"`
	Fingerprint     string `proxy:"client-fingerprint,omitempty"`
	Mode            string `proxy:"mode,omitempty"`
	QuicFingerprint string `proxy:"quic-fp,omitempty"`
	QuicPSK         string `proxy:"quic-psk,omitempty"`
	AutoQUICTimeout int    `proxy:"auto-quic-timeout,omitempty"`
	UDP             *bool  `proxy:"udp,omitempty"`
	SkipCertVerify  bool   `proxy:"skip-cert-verify,omitempty"`
}

func metadataToChimeraAddr(metadata *C.Metadata) *chimera.Address {
	addr := &chimera.Address{Port: metadata.DstPort}
	if metadata.Host != "" {
		addr.Type = chimera.AtypDomain
		addr.Domain = metadata.Host
	} else if metadata.DstIP.Is4() {
		addr.Type = chimera.AtypIPv4
		addr.IP = metadata.DstIP.AsSlice()
	} else if metadata.DstIP.Is6() {
		addr.Type = chimera.AtypIPv6
		addr.IP = metadata.DstIP.AsSlice()
	} else {
		addr.Type = chimera.AtypDomain
		addr.Domain = metadata.Host
	}
	if addr.Domain == "" && !metadata.DstIP.IsValid() {
		addr.Type = chimera.AtypDomain
		addr.Domain = metadata.Host
	}
	return addr
}

func (c *Chimera) StreamConnContext(ctx context.Context, conn net.Conn, metadata *C.Metadata) (net.Conn, error) {
	if conn == nil {
		return c.dialSelected(ctx, metadata)
	}
	switch c.quicMode {
	case "tcp":
		return c.streamTCP(ctx, conn, metadata)
	case "quic":
		_ = conn.Close()
		return c.dialQUIC(ctx, metadata)
	case "auto":
		quicCtx, cancel := context.WithTimeout(ctx, c.autoQUICTimeout)
		quicConn, quicErr := c.dialQUIC(quicCtx, metadata)
		cancel()
		if quicErr == nil && quicConn != nil {
			_ = conn.Close()
			return quicConn, nil
		}
		if quicConn != nil {
			_ = quicConn.Close()
		}
		tcpConn, tcpErr := c.streamTCP(ctx, conn, metadata)
		if tcpErr != nil {
			return nil, fmt.Errorf("chimera auto: QUIC failed (%v), TCP failed: %w", quicErr, tcpErr)
		}
		return tcpConn, nil
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("chimera: unknown mode %q", c.quicMode)
	}
}

func (c *Chimera) dialSelected(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	switch c.quicMode {
	case "tcp":
		return c.dialTCP(ctx, metadata)
	case "quic":
		return c.dialQUIC(ctx, metadata)
	case "auto":
		if c.autoQUICTimeout <= 0 {
			return nil, errors.New("chimera: auto QUIC timeout must be positive")
		}
		quicCtx, cancel := context.WithTimeout(ctx, c.autoQUICTimeout)
		quicConn, quicErr := c.dialQUIC(quicCtx, metadata)
		cancel()
		if quicErr == nil && quicConn != nil {
			return quicConn, nil
		}
		if quicConn != nil {
			_ = quicConn.Close()
		}
		tcpConn, tcpErr := c.dialTCP(ctx, metadata)
		if tcpErr != nil {
			return nil, fmt.Errorf("chimera auto: QUIC failed (%v), TCP failed: %w", quicErr, tcpErr)
		}
		return tcpConn, nil
	default:
		return nil, fmt.Errorf("chimera: unknown mode %q", c.quicMode)
	}
}

func (c *Chimera) dialTCP(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	if c.dialTCPFn != nil {
		return c.dialTCPFn(ctx, metadata)
	}
	conn, err := c.dialer.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", c.addr, err)
	}
	return c.streamTCP(ctx, conn, metadata)
}

func (c *Chimera) dialQUIC(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	if c.dialQUICFn != nil {
		return c.dialQUICFn(ctx, metadata)
	}
	return c.streamQUIC(ctx, metadata)
}

func (c *Chimera) streamTCP(ctx context.Context, conn net.Conn, metadata *C.Metadata) (net.Conn, error) {
	realityConn, err := tlsC.GetRealityConn(ctx, conn, c.clientFingerprint, c.option.SNI, c.realityConfig)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%s connect error: %w", c.addr, err)
	}
	if err := chimera.WriteSessionHeader(realityConn, 0x01); err != nil {
		_ = realityConn.Close()
		return nil, fmt.Errorf("%s session header: %w", c.addr, err)
	}
	status, err := chimera.ReadSessionResponse(realityConn)
	if err != nil {
		_ = realityConn.Close()
		return nil, fmt.Errorf("%s session response: %w", c.addr, err)
	}
	if status != chimera.StatusOK {
		_ = realityConn.Close()
		return nil, fmt.Errorf("%s server rejected: status %d", c.addr, status)
	}
	paddingConn := chimera.NewPadConn(realityConn)
	if err := chimera.WriteTargetConnect(paddingConn, chimera.CmdConnect, metadataToChimeraAddr(metadata)); err != nil {
		_ = paddingConn.Close()
		return nil, fmt.Errorf("%s target connect: %w", c.addr, err)
	}
	status, err = chimera.ReadSessionResponse(paddingConn)
	if err != nil {
		_ = paddingConn.Close()
		return nil, fmt.Errorf("%s connect result: %w", c.addr, err)
	}
	if status != chimera.StatusOK {
		_ = paddingConn.Close()
		return nil, fmt.Errorf("%s server dial failed: status %d", c.addr, status)
	}
	return paddingConn, nil
}

func (c *Chimera) streamQUIC(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	tlsConfig, err := chimera.NewPinnedTLSConfig(c.option.SNI, c.quicFP)
	if err != nil {
		return nil, fmt.Errorf("%s QUIC TLS: %w", c.addr, err)
	}
	quicConfig := chimera.DefaultQUICConfig(false)
	packetConn, quicConn, err := common.DialQuic(ctx, c.addr, c.DialOptions(), c.dialer, tlsConfig, quicConfig, common.DialQuicOption{ConnectionIDLength: 20})
	if err != nil {
		return nil, fmt.Errorf("%s QUIC dial: %w", c.addr, err)
	}
	client, err := chimera.NewQuicClientFromConn(quicConn, packetConn, c.option.SNI, c.quicAuthKey, false)
	if err != nil {
		_ = packetConn.Close()
		_ = quicConn.CloseWithError(0, "client setup failed")
		return nil, fmt.Errorf("%s QUIC client: %w", c.addr, err)
	}
	stream, err := client.DialTarget(ctx, metadataToChimeraAddr(metadata))
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("%s QUIC target: %w", c.addr, err)
	}
	return stream, nil
}

func (c *Chimera) listenPacketQUIC(ctx context.Context, metadata *C.Metadata) (net.PacketConn, error) {
	if c.listenPacketQUICFn != nil {
		return c.listenPacketQUICFn(ctx, metadata)
	}
	tlsConfig, err := chimera.NewPinnedTLSConfig(c.option.SNI, c.quicFP)
	if err != nil {
		return nil, fmt.Errorf("%s QUIC TLS: %w", c.addr, err)
	}
	quicConfig := chimera.DefaultQUICConfig(true)
	packetConn, quicConn, err := common.DialQuic(ctx, c.addr, c.DialOptions(), c.dialer, tlsConfig, quicConfig, common.DialQuicOption{ConnectionIDLength: 20})
	if err != nil {
		return nil, fmt.Errorf("%s QUIC dial: %w", c.addr, err)
	}
	client, err := chimera.NewQuicClientFromConn(quicConn, packetConn, c.option.SNI, c.quicAuthKey, true)
	if err != nil {
		_ = packetConn.Close()
		_ = quicConn.CloseWithError(0, "client setup failed")
		return nil, fmt.Errorf("%s QUIC client: %w", c.addr, err)
	}
	packetConn, err = client.DialUDP(ctx, metadataToChimeraAddr(metadata))
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("%s QUIC UDP target: %w", c.addr, err)
	}
	return packetConn, nil
}

func (c *Chimera) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	conn, err := c.dialSelected(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, c), nil
}

func (c *Chimera) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if c.Base == nil || !c.Base.SupportUDP() {
		return nil, errors.New("chimera: UDP is disabled")
	}
	if c.quicMode == "tcp" {
		return nil, errors.New("chimera: TCP mode does not support UDP")
	}
	if c.quicMode != "quic" && c.quicMode != "auto" {
		return nil, fmt.Errorf("chimera: unknown mode %q", c.quicMode)
	}
	pc, err := c.listenPacketQUIC(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return NewPacketConn(pc, c), nil
}

func (c *Chimera) ProxyInfo() C.ProxyInfo {
	info := c.Base.ProxyInfo()
	info.DialerProxy = c.option.DialerProxy
	return info
}

func NewChimera(option ChimeraOption) (*Chimera, error) {
	realityConfig, err := (RealityOptions{
		PublicKey: option.PublicKey,
		ShortID:   option.ShortID,
	}).Parse()
	if err != nil {
		return nil, err
	}
	if realityConfig == nil {
		return nil, errors.New("chimera: missing public-key")
	}

	clientFingerprint, ok := tlsC.GetFingerprint(option.Fingerprint)
	if !ok {
		clientFingerprint, ok = tlsC.GetFingerprint("chrome")
		if !ok {
			return nil, errors.New("chimera: unknown fingerprint")
		}
	}

	mode := strings.ToLower(strings.TrimSpace(option.Mode))
	if mode == "" {
		mode = "tcp"
	}
	if mode != "tcp" && mode != "quic" && mode != "auto" {
		return nil, fmt.Errorf("chimera: unknown mode %q (want tcp, quic or auto)", mode)
	}
	if option.AutoQUICTimeout < 0 || option.AutoQUICTimeout > 60_000 {
		return nil, errors.New("chimera: auto-quic-timeout must be between 1 and 60000 milliseconds, or 0 for default")
	}
	autoQUICTimeout := defaultChimeraAutoQUICTimeout
	if option.AutoQUICTimeout > 0 {
		autoQUICTimeout = time.Duration(option.AutoQUICTimeout) * time.Millisecond
	}

	var quicAuthKey []byte
	quicFingerprint := strings.TrimSpace(option.QuicFingerprint)
	if mode != "tcp" {
		if strings.TrimSpace(option.SNI) == "" {
			return nil, fmt.Errorf("chimera: mode %s requires sni", mode)
		}
		fingerprintBytes, err := hex.DecodeString(quicFingerprint)
		if err != nil || len(fingerprintBytes) != 32 {
			return nil, fmt.Errorf("chimera: mode %s requires a 64-character quic-fp", mode)
		}
		psk, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(option.QuicPSK))
		if err != nil || len(psk) != 32 {
			return nil, fmt.Errorf("chimera: mode %s requires a base64url-encoded 32-byte quic-psk", mode)
		}
		shortID, err := hex.DecodeString(strings.TrimSpace(option.ShortID))
		if err != nil || len(shortID) == 0 || len(shortID) > 8 {
			return nil, errors.New("chimera: invalid short-id for QUIC authentication")
		}
		quicAuthKey, err = chimera.DeriveAuthKey(psk, realityConfig.PublicKey.Bytes(), shortID)
		if err != nil {
			return nil, fmt.Errorf("chimera: derive QUIC authentication key: %w", err)
		}
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	udpEnabled := mode != "tcp"
	if option.UDP != nil {
		udpEnabled = udpEnabled && *option.UDP
	}
	outbound := &Chimera{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Chimera,
			ProviderName: option.ProviderName,
			UDP:          udpEnabled,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:            &option,
		realityConfig:     realityConfig,
		clientFingerprint: clientFingerprint,
		quicMode:          mode,
		quicAuthKey:       quicAuthKey,
		quicFP:            quicFingerprint,
		autoQUICTimeout:   autoQUICTimeout,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}
