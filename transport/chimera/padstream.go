package chimera

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"sync"
)

const (
	FramePaddingOnly = 0x00
	FrameDataWithPad = 0x01
	FrameDataNoPad   = 0x02
)

var ErrFrameTooLarge = errors.New("padstream: frame exceeds 65535 bytes")

// Policy controls padding behaviour.
type Policy struct {
	// MaxPadding is the upper bound for padding length on data frames.
	MaxPadding uint16
	// InitialFrames is how many frames at session start get extra padding.
	InitialFrames int
	// InitialMax is the upper bound for the first InitialFrames.
	InitialMax uint16
	// KeepAliveChance: 0-100 percentage chance of sending a padding-only frame.
	KeepAliveChance int
}

func DefaultPolicy() Policy {
	return Policy{
		MaxPadding:      64,
		InitialFrames:   8,
		InitialMax:      255,
		KeepAliveChance: 20,
	}
}

func randInt(max uint16) uint16 {
	if max == 0 {
		return 0
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)+1))
	return uint16(n.Int64())
}

func shouldKeepAlive(chance int) bool {
	if chance <= 0 {
		return false
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(100))
	return int(n.Int64()) < chance
}

// Conn wraps a net.Conn (typically a REALITY TLS conn) with padding frames.
type PadStream struct {
	raw    io.ReadWriteCloser
	policy Policy

	writeMu     sync.Mutex
	framesSent  int
	readBuf     []byte
	readStage   int // 0=header, 1=padding, 2=payload
	readPayloadLen uint16
	readPadLen  uint16
	readPadSkip int
}

func NewPaddingStream(raw io.ReadWriteCloser, p Policy) *PadStream {
	if p.InitialFrames <= 0 {
		p.InitialFrames = 8
	}
	if p.InitialMax == 0 {
		p.InitialMax = 255
	}
	return &PadStream{raw: raw, policy: p}
}

func (c *PadStream) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > 65535 {
			chunk = chunk[:65535]
		}
		var padLen uint16
		var frameType byte
		if c.framesSent < c.policy.InitialFrames {
			padLen = randInt(c.policy.InitialMax)
			frameType = FrameDataWithPad
		} else {
			padLen = randInt(c.policy.MaxPadding)
			if padLen > 0 {
				frameType = FrameDataWithPad
			} else {
				frameType = FrameDataNoPad
			}
		}
		header := make([]byte, 5)
		header[0] = frameType
		binary.BigEndian.PutUint16(header[1:3], uint16(len(chunk)))
		binary.BigEndian.PutUint16(header[3:5], padLen)
		if _, err := c.raw.Write(header); err != nil {
			return total, err
		}
		if padLen > 0 {
			pad := make([]byte, padLen)
			rand.Read(pad)
			if _, err := c.raw.Write(pad); err != nil {
				return total, err
			}
		}
		n, err := c.raw.Write(chunk)
		total += n
		if err != nil {
			return total, err
		}
		b = b[n:]
		c.framesSent++
	}
	return total, nil

}

// sendKeepAlive sends a padding-only frame if dice roll succeeds.
func (c *PadStream) maybeKeepAlive() {
	if shouldKeepAlive(c.policy.KeepAliveChance) {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		padLen := randInt(c.policy.MaxPadding)
		header := make([]byte, 5)
		header[0] = FramePaddingOnly
		binary.BigEndian.PutUint16(header[1:3], 0)
		binary.BigEndian.PutUint16(header[3:5], padLen)
		c.raw.Write(header)
		if padLen > 0 {
			pad := make([]byte, padLen)
			rand.Read(pad)
			c.raw.Write(pad)
		}
	}
}

func (c *PadStream) Read(b []byte) (int, error) {
	for {
		if len(c.readBuf) > 0 {
			n := copy(b, c.readBuf)
			c.readBuf = c.readBuf[n:]
			return n, nil
		}
		switch c.readStage {
		case 0: // read 5-byte header
			header := make([]byte, 5)
			if _, err := io.ReadFull(c.raw, header); err != nil {
				return 0, err
			}
			c.readPayloadLen = binary.BigEndian.Uint16(header[1:3])
			c.readPadLen = binary.BigEndian.Uint16(header[3:5])
			c.readPadSkip = 0
			if c.readPadLen > 0 {
				c.readStage = 1
			} else if c.readPayloadLen > 0 {
				c.readStage = 2
			} else {
				// padding-only frame, loop again
			}
		case 1: // discard padding
			buf := make([]byte, c.readPadLen)
			if _, err := io.ReadFull(c.raw, buf); err != nil {
				return 0, err
			}
			if c.readPayloadLen > 0 {
				c.readStage = 2
			} else {
				c.readStage = 0
			}
		case 2: // read payload
			payload := make([]byte, c.readPayloadLen)
			if _, err := io.ReadFull(c.raw, payload); err != nil {
				return 0, err
			}
			c.readBuf = payload
			c.readStage = 0
		}
	}
}

func (c *PadStream) Close() error {
	return c.raw.Close()
}


