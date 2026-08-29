package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"

	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/chimera"
)

type Chimera struct {
	*Base
	option         *ChimeraOption
	realityConfig  *tlsC.RealityConfig
	clientFingerprint tlsC.UClientHelloID
}

type ChimeraOption struct {
	BasicOption
	Name              string         `proxy:"name"`
	Server            string         `proxy:"server"`
	Port              int            `proxy:"port"`
	SNI               string         `proxy:"sni"`
	ShortID           string         `proxy:"short-id,omitempty"`
	PublicKey         string         `proxy:"public-key"`
	Fingerprint       string         `proxy:"client-fingerprint,omitempty"`
	UDP               bool           `proxy:"udp,omitempty"`
	SkipCertVerify    bool           `proxy:"skip-cert-verify,omitempty"`
}

func metadataToChimeraAddr(metadata *C.Metadata) *chimera.Address {
	addr := &chimera.Address{Port: metadata.DstPort}
	if metadata.DstIP.Is4() {
		addr.Type = chimera.AtypIPv4
		addr.IP = metadata.DstIP.AsSlice()
	} else if metadata.DstIP.Is6() {
		addr.Type = chimera.AtypIPv6
		addr.IP = metadata.DstIP.AsSlice()
	} else {
		addr.Type = chimera.AtypDomain
		addr.Domain = metadata.Host
	}
	if addr.Domain == "" && metadata.DstIP.IsValid() == false {
		addr.Type = chimera.AtypDomain
		addr.Domain = metadata.Host
	}
	return addr
}

// StreamConnContext implements C.ProxyAdapter
func (c *Chimera) StreamConnContext(ctx context.Context, conn net.Conn, metadata *C.Metadata) (net.Conn, error) {
	realityConn, err := tlsC.GetRealityConn(ctx, conn, c.clientFingerprint, c.option.SNI, c.realityConfig)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", c.addr, err)
	}

	// Chimera session header
	if err := chimera.WriteSessionHeader(realityConn, 0x01); err != nil {
		realityConn.Close()
		return nil, fmt.Errorf("%s session header: %w", c.addr, err)
	}
	status, err := chimera.ReadSessionResponse(realityConn)
	if err != nil {
		realityConn.Close()
		return nil, fmt.Errorf("%s session response: %w", c.addr, err)
	}
	if status != chimera.StatusOK {
		realityConn.Close()
		return nil, fmt.Errorf("%s server rejected: status %d", c.addr, status)
	}

	// Padding stream
	pc := chimera.NewPadConn(realityConn)

	// Target connect
	if err := chimera.WriteTargetConnect(pc, chimera.CmdConnect, metadataToChimeraAddr(metadata)); err != nil {
		pc.Close()
		return nil, fmt.Errorf("%s target connect: %w", c.addr, err)
	}

	// Chimera v2: wait for the server's dial-confirmation so the connection
	// is only handed back once the target is actually established.
	status2, err := chimera.ReadSessionResponse(pc)
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("%s connect result: %w", c.addr, err)
	}
	if status2 != chimera.StatusOK {
		pc.Close()
		return nil, fmt.Errorf("%s server dial failed: status %d", c.addr, status2)
	}

	return pc, nil
}

// DialContext implements C.ProxyAdapter
func (c *Chimera) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	conn, err := c.dialer.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", c.addr, err)
	}
	defer func(conn net.Conn) {
		safeConnClose(conn, err)
	}(conn)

	conn, err = c.StreamConnContext(ctx, conn, metadata)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, c), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (c *Chimera) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	return nil, fmt.Errorf("chimera: UDP not supported yet")
}

// ProxyInfo implements C.ProxyAdapter
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
		return nil, fmt.Errorf("chimera: missing public-key")
	}

	clientFingerprint, ok := tlsC.GetFingerprint(option.Fingerprint)
	if !ok {
		clientFingerprint, ok = tlsC.GetFingerprint("chrome")
		if !ok {
			return nil, fmt.Errorf("chimera: unknown fingerprint")
		}
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &Chimera{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Chimera,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:            &option,
		realityConfig:     realityConfig,
		clientFingerprint: clientFingerprint,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}
