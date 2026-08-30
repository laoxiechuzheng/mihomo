package chimera

import (
	"bytes"
	"crypto/hmac"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// PadConn wraps padstream.Conn for use as a net.Conn in mihomo.
type PadConn struct {
	*PadStream
	net.Conn
}

func NewPadConn(raw io.ReadWriteCloser) *PadConn {
	pc := &PadConn{PadStream: NewPaddingStream(raw, DefaultPolicy())}
	if nc, ok := raw.(net.Conn); ok {
		pc.Conn = nc
	}
	return pc
}

func (pc *PadConn) Read(b []byte) (int, error)  { return pc.PadStream.Read(b) }
func (pc *PadConn) Write(b []byte) (int, error) { return pc.PadStream.Write(b) }
func (pc *PadConn) Close() error                { return pc.PadStream.Close() }

func DefaultPaddingPolicy() Policy {
	return DefaultPolicy()
}

const (
	MagicByte0      = 0x43 // 'C'
	MagicByte1      = 0x48 // 'H'
	MagicByte2      = 0x49 // 'I'
	MagicByte3      = 0x4D // 'M'
	ProtocolVersion = 0x01

	StatusOK              = 0x00
	StatusVersionMismatch = 0x01

	CmdConnect = 0x01
	CmdUDP     = 0x03

	AtypIPv4   = 0x01
	AtypDomain = 0x03
	AtypIPv6   = 0x04
)

var (
	ErrBadMagic        = errors.New("chimera: bad magic")
	ErrVersionMismatch = errors.New("chimera: version mismatch")
)

func WriteSessionHeader(w io.Writer, flags byte) error {
	header := make([]byte, 32)
	header[0] = MagicByte0
	header[1] = MagicByte1
	header[2] = MagicByte2
	header[3] = MagicByte3
	header[4] = ProtocolVersion
	header[5] = flags
	_, err := w.Write(header)
	return err
}

func ReadSessionHeader(r io.Reader) (byte, error) {
	header := make([]byte, 32)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, err
	}
	if header[0] != MagicByte0 || header[1] != MagicByte1 || header[2] != MagicByte2 || header[3] != MagicByte3 {
		return 0, ErrBadMagic
	}
	if header[4] != ProtocolVersion {
		return 0, ErrVersionMismatch
	}
	return header[5], nil
}

func WriteSessionResponse(w io.Writer, status byte) error {
	resp := make([]byte, 8)
	resp[0] = MagicByte0
	resp[1] = MagicByte1
	resp[2] = MagicByte2
	resp[3] = MagicByte3
	resp[4] = ProtocolVersion
	resp[5] = status
	_, err := w.Write(resp)
	return err
}

func ReadSessionResponse(r io.Reader) (byte, error) {
	resp := make([]byte, 8)
	if _, err := io.ReadFull(r, resp); err != nil {
		return 0, err
	}
	if resp[0] != MagicByte0 || resp[1] != MagicByte1 || resp[2] != MagicByte2 || resp[3] != MagicByte3 {
		return 0, ErrBadMagic
	}
	if resp[4] != ProtocolVersion {
		return 0, ErrVersionMismatch
	}
	return resp[5], nil
}

type Address struct {
	Type   byte
	IP     net.IP
	Domain string
	Port   uint16
}

func (a *Address) String() string {
	switch a.Type {
	case AtypDomain:
		return fmt.Sprintf("%s:%d", a.Domain, a.Port)
	default:
		return fmt.Sprintf("%s:%d", a.IP.String(), a.Port)
	}
}

func WriteAddress(w io.Writer, addr *Address) error {
	buf := make([]byte, 0, 260)
	switch addr.Type {
	case AtypIPv4:
		buf = append(buf, AtypIPv4)
		buf = append(buf, addr.IP.To4()...)
	case AtypDomain:
		buf = append(buf, AtypDomain)
		buf = append(buf, byte(len(addr.Domain)))
		buf = append(buf, addr.Domain...)
	case AtypIPv6:
		buf = append(buf, AtypIPv6)
		buf = append(buf, addr.IP.To16()...)
	default:
		return errors.New("chimera: unsupported address type")
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], addr.Port)
	buf = append(buf, port[:]...)
	_, err := w.Write(buf)
	return err
}

func ReadAddress(r io.Reader) (*Address, error) {
	var typeBuf [1]byte
	if _, err := io.ReadFull(r, typeBuf[:]); err != nil {
		return nil, err
	}
	addr := &Address{Type: typeBuf[0]}
	switch addr.Type {
	case AtypIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return nil, err
		}
		addr.IP = net.IP(ip[:])
	case AtypDomain:
		var lenBuf [1]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(r, domain); err != nil {
			return nil, err
		}
		addr.Domain = string(domain)
	case AtypIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return nil, err
		}
		addr.IP = net.IP(ip[:])
	default:
		return nil, fmt.Errorf("chimera: unsupported address type %d", addr.Type)
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return nil, err
	}
	addr.Port = binary.BigEndian.Uint16(portBuf[:])
	return addr, nil
}

func WriteTargetConnect(w io.Writer, cmd byte, addr *Address) error {
	if _, err := w.Write([]byte{cmd}); err != nil {
		return err
	}
	return WriteAddress(w, addr)
}

func ReadTargetConnect(r io.Reader) (byte, *Address, error) {
	var cmdBuf [1]byte
	if _, err := io.ReadFull(r, cmdBuf[:]); err != nil {
		return 0, nil, err
	}
	addr, err := ReadAddress(r)
	return cmdBuf[0], addr, err
}

// Relay copies data bidirectionally until one direction finishes.
func Relay(a, b io.ReadWriteCloser) error {
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()
	<-done
	a.Close()
	b.Close()
	<-done
	return nil
}

// GenerateKeyPair generates an x25519 keypair for REALITY.
func GenerateKeyPair() (privB64, pubB64 string, err error) {
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	pub := privKey.PublicKey().Bytes()
	priv := privKey.Bytes()
	return base64.RawURLEncoding.EncodeToString(priv),
		base64.RawURLEncoding.EncodeToString(pub), nil
}

// --- QUIC v2 protocol helpers (mirror of chimera-core internal/chimera v2) ---

const (
	QUICVersion  = 0x02
	QUICNonceLen = 8
	QUICHMACLen  = 32
	QUICHeaderLen = 4 + 1 + 1 + 1 + QUICNonceLen + QUICHMACLen

	QUICStatusOK        = 0x00
	QUICStatusDialError = 0x01
)

// WriteQUICConnect writes the v2 authed connect frame.
func WriteQUICConnect(w io.Writer, cmd byte, password string, addr *Address) error {
	nonce := make([]byte, QUICNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write(nonce)
	auth := mac.Sum(nil)

	buf := make([]byte, 0, QUICHeaderLen+8+len(addr.Domain))
	buf = append(buf, MagicByte0, MagicByte1, MagicByte2, MagicByte3)
	buf = append(buf, QUICVersion)
	buf = append(buf, cmd)
	buf = append(buf, QUICNonceLen)
	buf = append(buf, nonce...)
	buf = append(buf, auth...)
	var addrBuf bytes.Buffer
	if err := WriteAddress(&addrBuf, addr); err != nil {
		return err
	}
	buf = append(buf, addrBuf.Bytes()...)
	_, err := w.Write(buf)
	return err
}

// ReadQUICResult reads the server's dial-confirmation frame.
func ReadQUICResult(r io.Reader) (byte, error) {
	resp := make([]byte, 8)
	if _, err := io.ReadFull(r, resp); err != nil {
		return 0, err
	}
	if resp[0] != MagicByte0 || resp[1] != MagicByte1 || resp[2] != MagicByte2 || resp[3] != MagicByte3 {
		return 0, ErrBadMagic
	}
	if resp[4] != QUICVersion {
		return 0, ErrVersionMismatch
	}
	return resp[5], nil
}

