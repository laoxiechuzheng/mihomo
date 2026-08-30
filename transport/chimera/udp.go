package chimera

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	mquic "github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
)

type DatagramConn struct {
	stream     *http3.RequestStream
	local      net.Addr
	remote     net.Addr
	target     net.Addr
	maxPacket  int
	ctx        context.Context
	cancel     context.CancelFunc
	closeOwner func() error
	encoder    *udpFragmentEncoder
	decoder    *udpFragmentDecoder

	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
	closeOnce     sync.Once
	closeErr      error
}

type udpTargetAddr struct{ authority string }

func (a udpTargetAddr) Network() string { return "udp" }
func (a udpTargetAddr) String() string  { return a.authority }

func newDatagramConn(stream *http3.RequestStream, local, remote, target net.Addr, maxPacket int, closeOwner func() error) *DatagramConn {
	if maxPacket <= 0 {
		maxPacket = defaultUDPMaxPacketSize
	}
	ctx, cancel := context.WithCancel(stream.Context())
	return &DatagramConn{
		stream:     stream,
		local:      local,
		remote:     remote,
		target:     target,
		maxPacket:  maxPacket,
		ctx:        ctx,
		cancel:     cancel,
		closeOwner: closeOwner,
		encoder:    newUDPFragmentEncoder(maxPacket),
		decoder:    newUDPFragmentDecoder(maxPacket),
	}
}

func (c *DatagramConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c == nil || c.stream == nil {
		return 0, nil, net.ErrClosed
	}
	ctx, cancel := c.readContext()
	defer cancel()
	for {
		data, err := c.stream.ReceiveDatagram(ctx)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			return 0, nil, err
		}
		packet, err := c.decoder.Decode(data)
		if err != nil {
			return 0, nil, err
		}
		if packet == nil {
			continue
		}
		return copy(p, packet), c.target, nil
	}
}

func (c *DatagramConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c == nil || c.stream == nil {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, errors.New("chimera-h3: empty UDP datagram")
	}
	if len(p) > c.maxPacket {
		return 0, errors.New("chimera-h3: UDP datagram exceeds configured size")
	}
	deadline := c.getWriteDeadline()
	if !deadline.IsZero() && time.Now().After(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if err := c.stream.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	frames, err := c.encoder.Encode(p)
	if err != nil {
		return 0, err
	}
	for _, frame := range frames {
		if err := c.stream.SendDatagram(frame); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (c *DatagramConn) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.cancel()
		if c.stream != nil {
			c.stream.CancelRead(mquic.StreamErrorCode(http3.ErrCodeRequestCanceled))
			c.stream.CancelWrite(mquic.StreamErrorCode(http3.ErrCodeRequestCanceled))
			c.closeErr = c.stream.Close()
		}
		if c.closeOwner != nil {
			if err := c.closeOwner(); err != nil && c.closeErr == nil {
				c.closeErr = err
			}
		}
	})
	return c.closeErr
}

func (c *DatagramConn) LocalAddr() net.Addr  { return c.local }
func (c *DatagramConn) RemoteAddr() net.Addr { return c.remote }

func (c *DatagramConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	c.mu.Unlock()
	if c.stream == nil {
		return net.ErrClosed
	}
	return c.stream.SetDeadline(deadline)
}

func (c *DatagramConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.mu.Unlock()
	if c.stream == nil {
		return net.ErrClosed
	}
	return c.stream.SetReadDeadline(deadline)
}

func (c *DatagramConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.writeDeadline = deadline
	c.mu.Unlock()
	if c.stream == nil {
		return net.ErrClosed
	}
	return c.stream.SetWriteDeadline(deadline)
}

func (c *DatagramConn) readContext() (context.Context, context.CancelFunc) {
	c.mu.Lock()
	deadline := c.readDeadline
	c.mu.Unlock()
	if deadline.IsZero() {
		return context.WithCancel(c.ctx)
	}
	return context.WithDeadline(c.ctx, deadline)
}

func (c *DatagramConn) getWriteDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeDeadline
}

var _ net.PacketConn = (*DatagramConn)(nil)
