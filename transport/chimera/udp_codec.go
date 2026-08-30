package chimera

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

const (
	defaultUDPMaxPacketSize  = 16 * 1024
	udpFragmentVersion       = byte(2)
	udpFragmentHeaderSize    = 7
	udpFragmentPayloadSize   = 1000
	udpFragmentMaxCount      = 64
	udpFragmentMaxAssemblies = 16
	udpFragmentAssemblyTTL   = 2 * time.Second
)

type udpFragmentEncoder struct {
	mu        sync.Mutex
	maxPacket int
	nextSeq   uint32
}

func newUDPFragmentEncoder(maxPacket int) *udpFragmentEncoder {
	if maxPacket <= 0 {
		maxPacket = defaultUDPMaxPacketSize
	}
	return &udpFragmentEncoder{maxPacket: maxPacket}
}

func (e *udpFragmentEncoder) Encode(packet []byte) ([][]byte, error) {
	if len(packet) == 0 {
		return nil, errors.New("chimera-h3: empty UDP packet")
	}
	if len(packet) > e.maxPacket {
		return nil, errors.New("chimera-h3: UDP packet exceeds configured size")
	}
	count := (len(packet) + udpFragmentPayloadSize - 1) / udpFragmentPayloadSize
	if count == 0 || count > udpFragmentMaxCount {
		return nil, errors.New("chimera-h3: UDP packet requires too many fragments")
	}
	e.mu.Lock()
	sequence := e.nextSeq
	e.nextSeq++
	e.mu.Unlock()
	frames := make([][]byte, 0, count)
	for index, offset := 0, 0; offset < len(packet); index, offset = index+1, offset+udpFragmentPayloadSize {
		end := min(offset+udpFragmentPayloadSize, len(packet))
		frame := make([]byte, udpFragmentHeaderSize+end-offset)
		frame[0] = udpFragmentVersion
		binary.BigEndian.PutUint32(frame[1:5], sequence)
		frame[5] = byte(index)
		frame[6] = byte(count)
		copy(frame[udpFragmentHeaderSize:], packet[offset:end])
		frames = append(frames, frame)
	}
	return frames, nil
}

type udpFragmentDecoder struct {
	mu        sync.Mutex
	maxPacket int
	pending   map[uint32]*udpFragmentAssembly
	now       func() time.Time
}

type udpFragmentAssembly struct {
	count     int
	parts     [][]byte
	received  int
	total     int
	expiresAt time.Time
}

func newUDPFragmentDecoder(maxPacket int) *udpFragmentDecoder {
	if maxPacket <= 0 {
		maxPacket = defaultUDPMaxPacketSize
	}
	return &udpFragmentDecoder{
		maxPacket: maxPacket,
		pending:   make(map[uint32]*udpFragmentAssembly, udpFragmentMaxAssemblies),
		now:       time.Now,
	}
}

func (d *udpFragmentDecoder) Decode(frame []byte) ([]byte, error) {
	if len(frame) <= udpFragmentHeaderSize || frame[0] != udpFragmentVersion {
		return nil, errors.New("chimera-h3: invalid UDP datagram frame")
	}
	sequence := binary.BigEndian.Uint32(frame[1:5])
	index := int(frame[5])
	count := int(frame[6])
	if count == 0 || count > udpFragmentMaxCount || index >= count {
		return nil, errors.New("chimera-h3: invalid UDP fragment index")
	}
	payload := frame[udpFragmentHeaderSize:]
	if len(payload) == 0 || len(payload) > udpFragmentPayloadSize {
		return nil, errors.New("chimera-h3: invalid UDP fragment size")
	}
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneExpiredLocked(now)
	assembly := d.pending[sequence]
	if assembly == nil {
		if len(d.pending) >= udpFragmentMaxAssemblies {
			d.evictOldestLocked()
		}
		assembly = &udpFragmentAssembly{
			count:     count,
			parts:     make([][]byte, count),
			expiresAt: now.Add(udpFragmentAssemblyTTL),
		}
		d.pending[sequence] = assembly
	} else if assembly.count != count {
		delete(d.pending, sequence)
		return nil, errors.New("chimera-h3: conflicting UDP fragment count")
	}
	if assembly.parts[index] != nil {
		return nil, nil
	}
	if assembly.total+len(payload) > d.maxPacket {
		delete(d.pending, sequence)
		return nil, errors.New("chimera-h3: UDP packet exceeds configured size")
	}
	assembly.parts[index] = append([]byte(nil), payload...)
	assembly.received++
	assembly.total += len(payload)
	if assembly.received != assembly.count {
		return nil, nil
	}
	packet := make([]byte, 0, assembly.total)
	for _, part := range assembly.parts {
		if part == nil {
			return nil, errors.New("chimera-h3: incomplete UDP fragment assembly")
		}
		packet = append(packet, part...)
	}
	delete(d.pending, sequence)
	return packet, nil
}

func (d *udpFragmentDecoder) pendingCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.pending)
}

func (d *udpFragmentDecoder) pruneExpiredLocked(now time.Time) {
	for sequence, assembly := range d.pending {
		if !assembly.expiresAt.After(now) {
			delete(d.pending, sequence)
		}
	}
}

func (d *udpFragmentDecoder) evictOldestLocked() {
	var oldestSequence uint32
	var oldestExpiry time.Time
	found := false
	for sequence, assembly := range d.pending {
		if !found || assembly.expiresAt.Before(oldestExpiry) {
			oldestSequence = sequence
			oldestExpiry = assembly.expiresAt
			found = true
		}
	}
	if found {
		delete(d.pending, oldestSequence)
	}
}
