# Chimera v0.6 in mihomo

This fork adds a native `type: chimera` outbound while retaining the normal mihomo protocols, DNS engine, rule engine, system proxy, and `with_gvisor` TUN support.

The v0.5 QUIC carrier is a standards-valid HTTP/3 basic CONNECT tunnel. v0.6 adds authenticated UDP associations over HTTP Datagrams. It remains incompatible with v0.3/v0.4 raw Chimera QUIC; upgrade the server and mihomo core together before using UDP.

## Configuration

```yaml
proxies:
  - name: chimera
    type: chimera
    server: YOUR_VPS_IP
    port: 9443
    sni: g.alicdn.com
    public-key: "YOUR_REALITY_PUBLIC_KEY"
    short-id: "YOUR_SHORT_ID"
    client-fingerprint: chrome
    mode: auto
    udp: true
    quic-psk: "YOUR_QUIC_PSK"
    quic-fp: "YOUR_QUIC_CERT_SHA256"
    auto-quic-timeout: 1200
```

Fields:

- `mode`: `tcp`, `quic`, or `auto`; default is `tcp`.
- `quic-psk`: base64url-encoded independent 32-byte PSK printed by the matching server installer.
- `quic-fp`: 64-character SHA-256 fingerprint of the QUIC leaf certificate.
- `auto-quic-timeout`: QUIC selection budget in milliseconds; `0` uses 1200 ms, maximum 60000 ms.
- `public-key` and `short-id`: the existing REALITY client credentials. They are also bound into the H3 auth-key derivation.
- `udp`: optional. It defaults to enabled in `quic` and `auto`; set `udp: false` to disable UDP capability explicitly. TCP mode never carries UDP.

`quic-psk` and `quic-fp` are mandatory for `quic` and `auto`, and are not needed for `tcp`.

## Mode behavior

- `tcp` opens only TCP/REALITY.
- `quic` opens only UDP/HTTP3. It does not pre-connect TCP, so it can work when the server's TCP path is blocked but UDP remains usable.
- `auto` tries QUIC for the configured budget. Only after failure does it create TCP/REALITY. QUIC success leaves no speculative TCP socket.

For UDP flows, `quic` and `auto` open a single-target authenticated H3 Datagram association. `auto` has no TCP fallback for UDP: if the UDP/QUIC path is unavailable, that UDP flow fails rather than being silently changed into TCP. TCP flows retain the regular bounded QUIC-first, TCP/REALITY-fallback behavior.

The relay fragments packets larger than one safe QUIC payload into encrypted H3 Datagrams and reassembles them with a 2-second expiry. It is still an unreliable datagram path: dropped fragments mean the original UDP packet is dropped. Default maximum UDP payload is 16 KiB; packets beyond that are rejected.

## Clash-compatible GUIs and TUN

Use the matching Windows `with_gvisor` release binary as the GUI's custom mihomo core, restart the core, then load the configuration above. TUN behavior remains the upstream mihomo implementation; on Windows it still requires the GUI/service to have the privileges needed to create and route the TUN interface. Chimera QUIC now uses Mihomo's managed packet dialer, so the QUIC socket follows the configured interface/routing mark and is not opened as an unmanaged socket that TUN can recapture.

The precise menu name differs between GUI versions. Confirm the running core/version in the GUI logs rather than assuming that replacing a file succeeded.

## Security notes

- QUIC requires certificate pinning and an independent PSK; there is no default or public password.
- Request authentication includes a timestamp, 16-byte random nonce, HMAC-SHA256, target authority, and SNI.
- The self-signed pinned certificate authenticates the server to configured clients, but it is not REALITY-equivalent active-probe camouflage.
- QUIC uses real HTTP/3 control streams, SETTINGS, QPACK, HEADERS, and DATA frames. It does not advertise `h3` while writing HTTP/1.1 or custom `CHIM` frames.
- UDP is carried inside encrypted HTTP Datagrams with strict packet, fragment, expiry, concurrency, target-validation, and source-filter limits; it is not sent as raw unauthenticated UDP from the server.
- Application-level HTTPS/SSH encryption remains necessary for sensitive content.

See the matching `chimera-core` README and `chimera-spec.md` for server installation, the complete wire contract, and limitations.
