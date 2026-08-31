package chimera

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	defaultUDPAssociationLimit       = 32
	defaultUDPAssociationIdleTimeout = time.Minute
	defaultUDPAssociationDialTimeout = 10 * time.Second
)

type DatagramMux struct {
	client      *QuicClient
	ctx         context.Context
	cancel      context.CancelFunc
	maxActive   int
	idleTimeout time.Duration
	reads       chan datagramMuxRead

	mu                  sync.Mutex
	associations        map[string]*datagramMuxAssociation
	pending             map[string]*datagramMuxPending
	readDeadline        time.Time
	writeDeadline       time.Time
	readDeadlineChanged chan struct{}
	closeOnce           sync.Once
	closeErr            error
}

type datagramMuxAssociation struct {
	key      string
	conn     *DatagramConn
	target   *net.UDPAddr
	lastUsed time.Time
	writeMu  sync.Mutex
}

type datagramMuxPending struct {
	done  chan struct{}
	entry *datagramMuxAssociation
	err   error
}

type datagramMuxRead struct {
	data   []byte
	target *net.UDPAddr
}

func (q *QuicClient) DialUDPMux(ctx context.Context) (*DatagramMux, error) {
	if q == nil || q.h3 == nil || !q.enableDatagrams {
		return nil, errors.New("chimera-h3: HTTP Datagrams are not enabled")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return newDatagramMux(q, defaultUDPAssociationLimit, defaultUDPAssociationIdleTimeout), nil
}

func newDatagramMux(client *QuicClient, maxActive int, idleTimeout time.Duration) *DatagramMux {
	if maxActive <= 0 {
		maxActive = defaultUDPAssociationLimit
	}
	if idleTimeout <= 0 {
		idleTimeout = defaultUDPAssociationIdleTimeout
	}
	ctx, cancel := context.WithCancel(context.Background())
	mux := &DatagramMux{
		client:              client,
		ctx:                 ctx,
		cancel:              cancel,
		maxActive:           maxActive,
		idleTimeout:         idleTimeout,
		reads:               make(chan datagramMuxRead, maxActive*2),
		associations:        make(map[string]*datagramMuxAssociation, maxActive),
		pending:             make(map[string]*datagramMuxPending),
		readDeadlineChanged: make(chan struct{}),
	}
	go mux.reapIdleAssociations()
	return mux
}

func (m *DatagramMux) WriteTo(payload []byte, destination net.Addr) (int, error) {
	if m == nil || m.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	address, key, target, err := addressFromUDPAddr(destination)
	if err != nil {
		return 0, err
	}
	deadline := m.getWriteDeadline()
	if !deadline.IsZero() && !deadline.After(time.Now()) {
		return 0, os.ErrDeadlineExceeded
	}
	for attempt := 0; attempt < 2; attempt++ {
		association, err := m.getOrCreateAssociation(address, key, target, deadline)
		if err != nil {
			return 0, err
		}
		association.writeMu.Lock()
		if err := association.conn.SetWriteDeadline(deadline); err != nil {
			association.writeMu.Unlock()
			return 0, err
		}
		n, err := association.conn.WriteTo(payload, target)
		association.writeMu.Unlock()
		if err == nil {
			m.touchAssociation(association, time.Now())
			return n, nil
		}
		if errors.Is(err, errUDPSequenceExhausted) && attempt == 0 {
			m.removeAssociation(association)
			continue
		}
		return n, err
	}
	return 0, errUDPSequenceExhausted
}

func (m *DatagramMux) ReadFrom(payload []byte) (int, net.Addr, error) {
	if m == nil || m.ctx.Err() != nil {
		return 0, nil, net.ErrClosed
	}
	for {
		deadline, changed := m.getReadDeadline()
		var timer *time.Timer
		var deadlineC <-chan time.Time
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(remaining)
			deadlineC = timer.C
		}

		select {
		case result := <-m.reads:
			if timer != nil {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			}
			return copy(payload, result.data), cloneUDPAddr(result.target), nil
		case <-deadlineC:
			return 0, nil, os.ErrDeadlineExceeded
		case <-changed:
			if timer != nil && !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			continue
		case <-m.ctx.Done():
			if timer != nil && !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return 0, nil, net.ErrClosed
		}
	}
}

func (m *DatagramMux) Close() error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(func() {
		m.cancel()
		m.mu.Lock()
		entries := make([]*datagramMuxAssociation, 0, len(m.associations))
		for _, entry := range m.associations {
			entries = append(entries, entry)
		}
		m.associations = make(map[string]*datagramMuxAssociation)
		m.mu.Unlock()
		for _, entry := range entries {
			if err := entry.conn.Close(); err != nil && m.closeErr == nil {
				m.closeErr = err
			}
		}
		if m.client != nil {
			if err := m.client.Close(); err != nil && m.closeErr == nil {
				m.closeErr = err
			}
		}
		m.signalReadDeadlineChange()
	})
	return m.closeErr
}

func (m *DatagramMux) LocalAddr() net.Addr {
	if m == nil || m.client == nil || m.client.conn == nil {
		return nil
	}
	return m.client.conn.LocalAddr()
}

func (m *DatagramMux) SetDeadline(deadline time.Time) error {
	if m == nil || m.ctx.Err() != nil {
		return net.ErrClosed
	}
	m.mu.Lock()
	m.readDeadline = deadline
	m.writeDeadline = deadline
	m.mu.Unlock()
	m.signalReadDeadlineChange()
	return nil
}

func (m *DatagramMux) SetReadDeadline(deadline time.Time) error {
	if m == nil || m.ctx.Err() != nil {
		return net.ErrClosed
	}
	m.mu.Lock()
	m.readDeadline = deadline
	m.mu.Unlock()
	m.signalReadDeadlineChange()
	return nil
}

func (m *DatagramMux) SetWriteDeadline(deadline time.Time) error {
	if m == nil || m.ctx.Err() != nil {
		return net.ErrClosed
	}
	m.mu.Lock()
	m.writeDeadline = deadline
	m.mu.Unlock()
	return nil
}

func (m *DatagramMux) getOrCreateAssociation(address *Address, key string, target *net.UDPAddr, deadline time.Time) (*datagramMuxAssociation, error) {
	if m.client == nil {
		return nil, errors.New("chimera-h3: QUIC client is unavailable")
	}
	for {
		if m.ctx.Err() != nil {
			return nil, net.ErrClosed
		}
		now := time.Now()
		expired := m.takeExpiredAssociations(now)
		m.closeAssociations(expired)

		m.mu.Lock()
		if entry := m.associations[key]; entry != nil {
			entry.lastUsed = now
			m.mu.Unlock()
			return entry, nil
		}
		if pending := m.pending[key]; pending != nil {
			m.mu.Unlock()
			select {
			case <-pending.done:
				if pending.err != nil {
					return nil, pending.err
				}
				if pending.entry == nil {
					return nil, errors.New("chimera-h3: UDP association setup failed")
				}
				return pending.entry, nil
			case <-m.ctx.Done():
				return nil, net.ErrClosed
			}
		}
		if len(m.associations)+len(m.pending) >= m.maxActive {
			m.mu.Unlock()
			return nil, errors.New("chimera-h3: UDP association limit reached")
		}
		pending := &datagramMuxPending{done: make(chan struct{})}
		m.pending[key] = pending
		m.mu.Unlock()

		dialCtx, cancel := m.associationDialContext(deadline)
		conn, err := m.client.dialUDP(dialCtx, address, target, nil)
		cancel()

		m.mu.Lock()
		delete(m.pending, key)
		if err == nil && m.ctx.Err() == nil {
			entry := &datagramMuxAssociation{key: key, conn: conn, target: cloneUDPAddr(target), lastUsed: time.Now()}
			m.associations[key] = entry
			pending.entry = entry
		} else if err == nil {
			_ = conn.Close()
			err = net.ErrClosed
		}
		pending.err = err
		close(pending.done)
		entry := pending.entry
		m.mu.Unlock()

		if err != nil {
			return nil, err
		}
		go m.readAssociation(entry)
		return entry, nil
	}
}

func (m *DatagramMux) associationDialContext(deadline time.Time) (context.Context, context.CancelFunc) {
	if !deadline.IsZero() {
		return context.WithDeadline(m.ctx, deadline)
	}
	return context.WithTimeout(m.ctx, defaultUDPAssociationDialTimeout)
}

func (m *DatagramMux) readAssociation(entry *datagramMuxAssociation) {
	buffer := make([]byte, entry.conn.maxPacket)
	for {
		n, _, err := entry.conn.ReadFrom(buffer)
		if err != nil {
			if m.ctx.Err() == nil {
				m.removeAssociation(entry)
			}
			return
		}
		m.touchAssociation(entry, time.Now())
		result := datagramMuxRead{
			data:   append([]byte(nil), buffer[:n]...),
			target: cloneUDPAddr(entry.target),
		}
		select {
		case m.reads <- result:
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *DatagramMux) reapIdleAssociations() {
	interval := m.idleTimeout / 2
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.closeAssociations(m.takeExpiredAssociations(time.Now()))
		case <-m.ctx.Done():
			return
		}
	}
}

func (m *DatagramMux) takeExpiredAssociations(now time.Time) []*datagramMuxAssociation {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries := make([]*datagramMuxAssociation, 0)
	for key, entry := range m.associations {
		if now.Sub(entry.lastUsed) >= m.idleTimeout {
			delete(m.associations, key)
			entries = append(entries, entry)
		}
	}
	return entries
}

func (m *DatagramMux) closeAssociations(entries []*datagramMuxAssociation) {
	for _, entry := range entries {
		_ = entry.conn.Close()
	}
}

func (m *DatagramMux) removeAssociation(entry *datagramMuxAssociation) {
	m.mu.Lock()
	if m.associations[entry.key] == entry {
		delete(m.associations, entry.key)
	}
	m.mu.Unlock()
	_ = entry.conn.Close()
}

func (m *DatagramMux) touchAssociation(entry *datagramMuxAssociation, now time.Time) {
	m.mu.Lock()
	if m.associations[entry.key] == entry {
		entry.lastUsed = now
	}
	m.mu.Unlock()
}

func (m *DatagramMux) getReadDeadline() (time.Time, <-chan struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.readDeadline, m.readDeadlineChanged
}

func (m *DatagramMux) getWriteDeadline() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writeDeadline
}

func (m *DatagramMux) signalReadDeadlineChange() {
	m.mu.Lock()
	defer m.mu.Unlock()
	close(m.readDeadlineChanged)
	m.readDeadlineChanged = make(chan struct{})
}

func addressFromUDPAddr(addr net.Addr) (*Address, string, *net.UDPAddr, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil || udpAddr.Port <= 0 || udpAddr.Port > 65535 || udpAddr.Zone != "" {
		return nil, "", nil, errors.New("chimera-h3: UDP destination must be an IP address with a port")
	}
	ip, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok || !ip.IsValid() {
		return nil, "", nil, errors.New("chimera-h3: UDP destination must be an IP address with a port")
	}
	ip = ip.Unmap()
	target := &net.UDPAddr{IP: append(net.IP(nil), ip.AsSlice()...), Port: udpAddr.Port}
	address := &Address{IP: append(net.IP(nil), target.IP...), Port: uint16(target.Port)}
	if ip.Is4() {
		address.Type = AtypIPv4
	} else {
		address.Type = AtypIPv6
	}
	key := net.JoinHostPort(ip.String(), strconv.Itoa(target.Port))
	return address, key, target, nil
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}

var _ net.PacketConn = (*DatagramMux)(nil)
