package chimera

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestDatagramMuxRoutesPacketsToTheirWriteToDestination(t *testing.T) {
	key := bytes.Repeat([]byte{0x56}, 32)
	serverName := "proxy.example"
	serverAddr, fingerprint := startH3DatagramServer(t, serverName, key)
	first := startUDPEchoServer(t)
	second := startUDPEchoServer(t)
	firstAddr := first.LocalAddr().(*net.UDPAddr)
	secondAddr := second.LocalAddr().(*net.UDPAddr)

	client, err := DialQuicWithDatagrams(context.Background(), serverAddr, serverName, key, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	conn, err := client.DialUDPMux(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if _, err := conn.WriteTo([]byte("first-destination"), firstAddr); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteTo([]byte("second-destination"), secondAddr); err != nil {
		t.Fatal(err)
	}

	got := make(map[string]string, 2)
	buf := make([]byte, 1024)
	for range 2 {
		if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		udpAddr, ok := from.(*net.UDPAddr)
		if !ok {
			t.Fatalf("response address type = %T, want *net.UDPAddr", from)
		}
		got[udpAddr.String()] = string(buf[:n])
	}

	if got[firstAddr.String()] != "first-destination" {
		t.Fatalf("first target reply = %q, want %q", got[firstAddr.String()], "first-destination")
	}
	if got[secondAddr.String()] != "second-destination" {
		t.Fatalf("second target reply = %q, want %q", got[secondAddr.String()], "second-destination")
	}
}

func TestDatagramMuxRejectsInvalidTargetWithoutReusingAnExistingAssociation(t *testing.T) {
	key := bytes.Repeat([]byte{0x57}, 32)
	serverName := "proxy.example"
	serverAddr, fingerprint := startH3DatagramServer(t, serverName, key)
	echo := startUDPEchoServer(t)
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	client, err := DialQuicWithDatagrams(context.Background(), serverAddr, serverName, key, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	conn, err := client.DialUDPMux(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if _, err := conn.WriteTo([]byte("existing-target"), echoAddr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := conn.ReadFrom(buf); err != nil || string(buf[:n]) != "existing-target" {
		t.Fatalf("initial echo = %q, %v", buf[:n], err)
	}

	invalid := &net.UDPAddr{IP: append(net.IP(nil), echoAddr.IP...), Port: 0}
	if _, err := conn.WriteTo([]byte("must-not-reach-existing-target"), invalid); err == nil {
		t.Fatal("invalid target was accepted")
	}

	if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, from, err := conn.ReadFrom(buf); err == nil {
		t.Fatalf("invalid-target payload unexpectedly reached %v: %q", from, buf[:n])
	}
}

func TestDatagramMuxRejectsNewDestinationAtAssociationLimit(t *testing.T) {
	key := bytes.Repeat([]byte{0x58}, 32)
	serverName := "proxy.example"
	serverAddr, fingerprint := startH3DatagramServer(t, serverName, key)
	first := startUDPEchoServer(t)
	second := startUDPEchoServer(t)
	firstAddr := first.LocalAddr().(*net.UDPAddr)
	secondAddr := second.LocalAddr().(*net.UDPAddr)

	client, err := DialQuicWithDatagrams(context.Background(), serverAddr, serverName, key, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	mux := newDatagramMux(client, 1, time.Hour)
	t.Cleanup(func() { _ = mux.Close() })

	if _, err := mux.WriteTo([]byte("first-at-limit"), firstAddr); err != nil {
		t.Fatal(err)
	}
	if _, err := mux.WriteTo([]byte("must-not-reach-second"), secondAddr); err == nil {
		t.Fatal("second destination was accepted after reaching the association limit")
	}

	buf := make([]byte, 1024)
	if err := mux.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, from, err := mux.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "first-at-limit" {
		t.Fatalf("limit response = %q, want first destination only", got)
	}
	if got := from.(*net.UDPAddr).String(); got != firstAddr.String() {
		t.Fatalf("limit response source = %q, want %q", got, firstAddr)
	}

	if err := mux.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, from, err := mux.ReadFrom(buf); err == nil {
		t.Fatalf("limit-rejected payload unexpectedly reached %v: %q", from, buf[:n])
	}
}

func TestDatagramMuxReclaimsIdleDestinationBeforeOpeningAnother(t *testing.T) {
	key := bytes.Repeat([]byte{0x59}, 32)
	serverName := "proxy.example"
	serverAddr, fingerprint := startH3DatagramServer(t, serverName, key)
	first := startUDPEchoServer(t)
	second := startUDPEchoServer(t)
	firstAddr := first.LocalAddr().(*net.UDPAddr)
	secondAddr := second.LocalAddr().(*net.UDPAddr)

	client, err := DialQuicWithDatagrams(context.Background(), serverAddr, serverName, key, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	mux := newDatagramMux(client, 1, 30*time.Millisecond)
	t.Cleanup(func() { _ = mux.Close() })

	if _, err := mux.WriteTo([]byte("first-before-idle"), firstAddr); err != nil {
		t.Fatal(err)
	}
	readDatagramPayload(t, mux, "first-before-idle", firstAddr)

	deadline := time.Now().Add(time.Second)
	for {
		_, err = mux.WriteTo([]byte("second-after-idle"), secondAddr)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("idle association was not reclaimed: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	readDatagramPayload(t, mux, "second-after-idle", secondAddr)
}

func TestDatagramMuxReadDeadlineAndCloseAreObservable(t *testing.T) {
	mux := newDatagramMux(nil, 1, time.Hour)
	if err := mux.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mux.ReadFrom(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read deadline error = %v, want %v", err, os.ErrDeadlineExceeded)
	}
	if err := mux.Close(); err != nil {
		t.Fatal(err)
	}
	if err := mux.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mux.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after close = %v, want %v", err, net.ErrClosed)
	}
}

func TestDatagramMuxRejectsMissingQUICClient(t *testing.T) {
	mux := newDatagramMux(nil, 1, time.Hour)
	t.Cleanup(func() { _ = mux.Close() })
	if _, err := mux.WriteTo([]byte("no-client"), &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53}); err == nil {
		t.Fatal("mux accepted a write without a QUIC client")
	}
}

func TestDatagramMuxRotatesExhaustedAssociation(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, 32)
	serverName := "proxy.example"
	serverAddr, fingerprint := startH3DatagramServer(t, serverName, key)
	echo := startUDPEchoServer(t)
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	client, err := DialQuicWithDatagrams(context.Background(), serverAddr, serverName, key, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	mux := newDatagramMux(client, 2, time.Hour)
	t.Cleanup(func() { _ = mux.Close() })

	if _, err := mux.WriteTo([]byte("before-exhaustion"), echoAddr); err != nil {
		t.Fatal(err)
	}
	readDatagramPayload(t, mux, "before-exhaustion", echoAddr)

	_, associationKey, _, err := addressFromUDPAddr(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	mux.mu.Lock()
	first := mux.associations[associationKey]
	mux.mu.Unlock()
	if first == nil {
		t.Fatal("initial UDP association was not recorded")
	}
	first.conn.encoder.mu.Lock()
	first.conn.encoder.nextSeq = ^uint32(0)
	first.conn.encoder.mu.Unlock()

	if _, err := mux.WriteTo([]byte("last-sequence"), echoAddr); err != nil {
		t.Fatal(err)
	}
	readDatagramPayload(t, mux, "last-sequence", echoAddr)
	if _, err := mux.WriteTo([]byte("after-exhaustion"), echoAddr); err != nil {
		t.Fatal(err)
	}
	readDatagramPayload(t, mux, "after-exhaustion", echoAddr)

	mux.mu.Lock()
	second := mux.associations[associationKey]
	mux.mu.Unlock()
	if second == first {
		t.Fatal("exhausted association was reused after its fragment sequence wrapped")
	}
}

func readDatagramPayload(t *testing.T, conn net.PacketConn, want string, wantAddr *net.UDPAddr) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, from, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != want {
		t.Fatalf("reply payload = %q, want %q", got, want)
	}
	udpAddr, ok := from.(*net.UDPAddr)
	if !ok {
		t.Fatalf("reply address type = %T, want *net.UDPAddr", from)
	}
	if got := udpAddr.String(); got != wantAddr.String() {
		t.Fatalf("reply source = %q, want %q", got, wantAddr)
	}
}
