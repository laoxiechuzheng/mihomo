package chimera

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestUDPDatagramCodecMatchesCoreFragmentLayout(t *testing.T) {
	encoder := newUDPFragmentEncoder(4096)
	decoder := newUDPFragmentDecoder(4096)
	payload := bytes.Repeat([]byte("chimera"), 500)
	frames, err := encoder.Encode(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) < 2 {
		t.Fatalf("fragment count = %d, want >= 2", len(frames))
	}
	for i := len(frames) - 1; i >= 0; i-- {
		got, err := decoder.Decode(frames[i])
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 && !bytes.Equal(got, payload) {
			t.Fatalf("reassembled payload mismatch: got %d bytes, want %d", len(got), len(payload))
		}
	}
}

func TestUDPDatagramCodecDoesNotMixPacketsAfterLegacySequenceRange(t *testing.T) {
	encoder := newUDPFragmentEncoder(4096)
	decoder := newUDPFragmentDecoder(4096)
	first, err := encoder.Encode(bytes.Repeat([]byte("a"), 2000))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decoder.Decode(first[0]); err != nil || got != nil {
		t.Fatalf("first fragment = %x, %v; want incomplete packet", got, err)
	}
	// Simulate an association that has sent more than 65,535 packets while
	// the first fragmented packet is still incomplete.
	encoder.nextSeq = 65_535
	if _, err := encoder.Encode(bytes.Repeat([]byte("b"), 2000)); err != nil {
		t.Fatal(err)
	}
	second, err := encoder.Encode(bytes.Repeat([]byte("c"), 2000))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decoder.Decode(second[1]); err != nil || got != nil {
		t.Fatalf("wrapped sequence mixed %d-byte packet, err=%v; want incomplete packet", len(got), err)
	}
}

func TestUDPDatagramCodecDropsExpiredPartial(t *testing.T) {
	now := time.Unix(1_788_000_000, 0)
	encoder := newUDPFragmentEncoder(4096)
	decoder := newUDPFragmentDecoder(4096)
	decoder.now = func() time.Time { return now }
	frames, err := encoder.Encode(bytes.Repeat([]byte("x"), 2000))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Decode(frames[0]); err != nil {
		t.Fatal(err)
	}
	now = now.Add(udpFragmentAssemblyTTL + time.Second)
	if _, err := decoder.Decode(frames[1]); err != nil {
		t.Fatal(err)
	}
	if got := decoder.pendingCount(); got != 1 {
		t.Fatalf("pending assemblies = %d, want 1", got)
	}
}

func TestUDPDatagramCodecMatchesV06WireFixture(t *testing.T) {
	frames, err := newUDPFragmentEncoder(64).Encode([]byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{2, 0, 0, 0, 0, 0, 1, 'a', 'b', 'c'}
	if len(frames) != 1 || !bytes.Equal(frames[0], want) {
		t.Fatalf("frame = %x, want %x", frames, want)
	}
}

func TestUDPDatagramCodecFailsClosedAfterMaxSequence(t *testing.T) {
	encoder := newUDPFragmentEncoder(64)
	encoder.nextSeq = ^uint32(0)
	frames, err := encoder.Encode([]byte("last"))
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 || binary.BigEndian.Uint32(frames[0][1:5]) != ^uint32(0) {
		t.Fatalf("last sequence frame = %x", frames)
	}
	if _, err := encoder.Encode([]byte("must-not-wrap")); err == nil {
		t.Fatal("fragment sequence wrapped instead of failing closed")
	}
}
