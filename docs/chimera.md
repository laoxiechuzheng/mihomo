# Chimera v0.5 in mihomo

This fork adds a native `type: chimera` outbound while retaining the normal mihomo protocols, DNS engine, rule engine, system proxy, and `with_gvisor` TUN support.

The v0.5 QUIC carrier is a standards-valid HTTP/3 basic CONNECT tunnel. It is incompatible with v0.3/v0.4 raw Chimera QUIC; upgrade the server and mihomo core together.

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
    quic-psk: "YOUR_QUIC_PSK"
    quic-fp: "YOUR_QUIC_CERT_SHA256"
    auto-quic-timeout: 1200
```

Fields:

- `mode`: `tcp`, `quic`, or `auto`; default is `tcp`.
- `quic-psk`: base64url-encoded independent 32-byte PSK printed by the v0.5 server installer.
- `quic-fp`: 64-character SHA-256 fingerprint of the QUIC leaf certificate.
- `auto-quic-timeout`: QUIC selection budget in milliseconds; `0` uses 1200 ms, maximum 60000 ms.
- `public-key` and `short-id`: the existing REALITY client credentials. They are also bound into the H3 auth-key derivation.

`quic-psk` and `quic-fp` are mandatory for `quic` and `auto`, and are not needed for `tcp`.

## Mode behavior

- `tcp` opens only TCP/REALITY.
- `quic` opens only UDP/HTTP3. It does not pre-connect TCP, so it can work when the server's TCP path is blocked but UDP remains usable.
- `auto` tries QUIC for the configured budget. Only after failure does it create TCP/REALITY. QUIC success leaves no speculative TCP socket.

The carrier being UDP does not make Chimera an arbitrary UDP proxy. The outbound currently exposes TCP connections only and deliberately reports `SupportUDP() == false`; UDP ASSOCIATE and CONNECT-UDP are not implemented.

## Clash-compatible GUIs and TUN

Use the matching Windows `with_gvisor` release binary as the GUI's custom mihomo core, restart the core, then load the configuration above. TUN behavior remains the upstream mihomo implementation; on Windows it still requires the GUI/service to have the privileges needed to create and route the TUN interface.

The precise menu name differs between GUI versions. Confirm the running core/version in the GUI logs rather than assuming that replacing a file succeeded.

## Security notes

- QUIC requires certificate pinning and an independent PSK; there is no default or public password.
- Request authentication includes a timestamp, 16-byte random nonce, HMAC-SHA256, target authority, and SNI.
- The self-signed pinned certificate authenticates the server to configured clients, but it is not REALITY-equivalent active-probe camouflage.
- QUIC uses real HTTP/3 control streams, SETTINGS, QPACK, HEADERS, and DATA frames. It does not advertise `h3` while writing HTTP/1.1 or custom `CHIM` frames.
- Application-level HTTPS/SSH encryption remains necessary for sensitive content.

See the matching `chimera-core` README and `chimera-spec.md` for server installation, the complete wire contract, and limitations.
