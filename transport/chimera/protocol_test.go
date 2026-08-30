package chimera

import (
	"bytes"
	"net"
	"strings"
	"testing"
)

func TestAddressStringBracketsIPv6(t *testing.T) {
	addr := &Address{Type: AtypIPv6, IP: net.ParseIP("2001:db8::1"), Port: 443}
	if got := addr.String(); got != "[2001:db8::1]:443" {
		t.Fatalf("address = %q", got)
	}
}

func TestWriteAddressRejectsInvalidDomainLength(t *testing.T) {
	for name, domain := range map[string]string{
		"empty": "",
		"long":  strings.Repeat("a", 256),
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteAddress(&buf, &Address{Type: AtypDomain, Domain: domain, Port: 443}); err == nil {
				t.Fatal("invalid domain accepted")
			}
		})
	}
}
