# Siglark

A self-hostable **NetherNet External Signaling (NXS v1)** provider for Minecraft: Bedrock Edition, written in Go.

Verified end-to-end with a real Bedrock client (2026-11): the client discovers the server through Siglark, completes the control-WebSocket assisted join, and lands in Paper via Geyser's `nxs` signaling mode.

## What is this?

NetherNet is the WebRTC-based transport Bedrock Edition is moving to. With the `nxs` transport, a Bedrock client talks to an external signaling service to discover servers and set up its WebRTC connection — the same role Mojang's hosted signaling plays. Siglark is an independent implementation of that service, so you can run the signaling yourself instead of depending on anyone's hosted instance.

## Features

- **Host lifecycle**: discovery document, `register`/`complete` (proof-of-work), heartbeat with lease tracking, `rotate`/`retire`/`recover`, `deregister`
- **Stateless admission**: join credentials are minted as AES-256-GCM tokens carried in the answer ufrag (`NXS1...`) — hosts hold no join state and every provider replica can serve any join
- **Client signaling**: `GET /v1/join` (listing), `POST /v1/join/{networkId}` (offer), `/v1/nxs/control` WebSocket (assisted joins)
- **Identity**: client identity verification (detached JWS, ES384, JWKS) and server identity assertions for assisted answers
- **Ops**: admin API (bearer token issue/revoke, registration listing, readiness), file-backed persistence, protocol test suite

## Quick start

Build and run:

```powershell
go build ./cmd/siglark
SIGLARK_CONFIG=path/to/config.yaml ./siglark
```

Minimal `config.yaml`:

```yaml
server:
  name: Siglark
  version: 0.1.0
  env: development

http:
  host: 0.0.0.0
  port: 8080

storage:
  driver: "file"
  path: "siglark-data.json"

nxs:
  provider_origin: "http://your-public-host:8080"
```

Point Geyser at it (`bedrock.signaling` in Geyser's `config.yml`):

```yaml
bedrock:
  transport: nethernet
  signaling:
    mode: nxs
    endpoint: http://your-siglark-host:8080
    advertise-addresses: [your-lan-or-public-ip]
  nxs:
    assisted-joins: true
```

Players connect exactly as they would with any NetherNet server: the Bedrock client reaches Siglark over HTTP(S), gets the listing, and joins via WebRTC. Siglark must be reachable from both the Geyser host (control WebSocket) and Bedrock clients (join endpoints) — put it behind TLS or a reverse proxy for anything beyond a LAN.

### Assisted-join identity (required by Bedrock clients)

Geyser's assisted-join path never emits a server identity assertion in its answer SDP, and Bedrock clients silently refuse to continue (no DTLS, on-screen `InitialConnection-142`). Siglark mints the assertion for the host, so tell it which identity to sign with:

```yaml
nxs:
  hosts:
    - host: "your-public-host"
      registration_id: "reg_..."        # from GET /v1/admin/registrations
      identity_pem: "path/to/identity.pem"   # P-384 PEM, e.g. Geyser's nethernet/identity.pem
      # identity_domain: "Siglark-SelfhostNXS"   # optional, this is the default
```

`identity_domain` is the namespace a client tracks the server identity under (first-use trust, like a SSH host-key record). If you change it on a server entry players already saved, the client sees a new identity for a known address: it may prompt for confirmation or refuse to connect with `InitialConnection-142`. Removing and re-adding the server entry in the client resets that state.

> **Security note:** this means the Siglark process holds the host's private identity key. That is fine when you operate both (the common self-hosted case: Geyser + Siglark on the same side). Long-term, hosts will upload their assertion material at registration so the provider never touches private keys — tracked on the roadmap.

## Client-side contract

A player enters `your-siglark-host:8080` in the Bedrock "Add Server" dialog. The client then talks to Siglark directly; Geyser is not in the signaling path.

| Endpoint | Purpose |
| --- | --- |
| `GET /v1/join` | Listing document (`dataVersion`, `protocol`, `version`, `name`, `players`, `transportLayer: 2`, `connection: 4`, `onlineAuth`, `selfSignedAuth`, `nonce`) |
| `POST /v1/join/{networkId}` | Body is the client's SDP offer (`application/sdp`); reply is the host's answer (`application/sdp`) |
| `WS /v1/nxs/control` | Provider ↔ host channel used for assisted joins (host side, not the player) |

Requests are routed by the HTTP `Host` header to the registration configured in `nxs.hosts`, so Siglark must receive exactly the hostname players typed. `networkId` is 1–20 decimal digits and only identifies the peer for de-duplication; it is not looked up against a registration.

### Offer requirements

The provider validates strictly and answers `400` when any rule fails:

- exactly one `m=application <port> UDP/DTLS/SCTP webrtc-datachannel`
- `a=setup:actpass`, `a=sctp-port:5000`, `a=max-message-size:262144`
- exactly one `a=ice-ufrag` (4–256 chars), `a=ice-pwd` (≥22 chars), `a=fingerprint:sha-256 …`
- no `a=ice-lite`
- 1–32 candidates, each component 1 / UDP / numeric IP literal

### Client identity (`a=identity`) — mandatory

Every offer must carry one `a=identity` attribute: standard base64 of `{"idp":{…},"assertion":"<escaped JSON string>"}`. The assertion holds:

- `token` — JWT issued by Minecraft's authorization service. Real clients sign with **RS256** and the `kid` resolves in its JWKS (`https://authorization.franchise.minecraft-services.net/.well-known/keys`, RSA keys). Claims include `cpk`, `xid`, `xname`, `exp`, `aud: api://auth-minecraft-services/multiplayer`, `iss: https://authorization.franchise.minecraft-services.net/`.
- `fingerprints` — a **detached ES384 JWS** (`<header>..<signature>`, empty payload segment) made with the client's own P-384 key (`cpk`) over the offer's canonical fingerprint JSON. This is what proves the client holds the key its token names.

The provider strips `a=identity` before forwarding the offer to the host (the host never sees the player's token) and derives the stateless admission binding from the verified `cpk` instead.

| `identity_trust` | Behavior | Use |
| --- | --- | --- |
| `minecraft` | Full JWKS signature check + `exp`/`sub`/`aud`/`iss` + ES384 possession proof | Production |
| `any` | `exp` only; possession proof still enforced | Development |

### Troubleshooting

| Symptom | Meaning |
| --- | --- |
| `401 client identity rejected` | Token expired, `aud`/`iss` mismatch, unsupported `alg` (only ES384/RS256/RS384/RS512), `cpk` not canonical P-384, or the detached JWS does not cover this offer's fingerprints |
| `404` on `GET /v1/join` | The `Host` header matches no `nxs.hosts` entry, the registration was removed, or its lease expired (host not heartbeating) |
| `503` on join | Host not accepting players, admission key not installed/acked, or the host profile lacks assisted-join data |
| `504` on join | The host did not return an answer within `assisted_join_timeout_ms` (its control WebSocket is down or its signaling is in `builtin` only) |
| Client shows `InitialConnection-142` and never loads terrain | The answer is missing `a=identity`, or its `c=`/candidates point somewhere the client cannot reach — see the quirks below |

## Known protocol quirks

Behavior we had to reverse-engineer because the wire spec leaves it open. If you implement your own provider, these will bite you:

1. **Assisted answers need a server identity assertion.** Bedrock clients require `a=identity` in the answer even though Geyser's assisted path never sends one. The assertion must match Geyser's builtin shape exactly: outer standard base64 of `{"idp":{"domain":"<name>","protocol":"default"},"assertion":"<escaped JSON string>"}` — note `assertion` is a **string**, not a nested object — wrapping `{"token":"<ES384 JWT with cpk/iat/iss>","fingerprints":"<header>..<sig>"}` where the fingerprints JWS is detached with an **empty payload segment** (two dots). Inserted before the first `m=` line. See `internal/nxs/identity_assert.go`, pinned by tests.
2. **Never rewrite the answer's `c=` line.** The host's connection line may point at a virtual adapter the client can actually reach (WSL, Hyper-V, VPN); replacing it with a "nicer" address can route DTLS into a proxy TUN and kill the handshake. Candidate lines are fair game.
3. **`selfSignedAuth` semantics differ by path.** Builtin signaling ships a full `a=identity` chain and lists `selfSignedAuth: false`; assisted answers use the provider's stateless admission plus a self-signed assertion, so the listing should say `selfSignedAuth: true`.

## Configuration

| Key | Meaning |
| --- | --- |
| `nxs.provider_origin` | Canonical public origin advertised in discovery; must match how clients reach Siglark |
| `nxs.hosts` | Maps an HTTP `Host` header to a registration ID (and optional `identity_pem`/`identity_domain`) |
| `nxs.identity_trust` | `minecraft` (JWKS signature + exp/sub/aud/iss, verified with real clients) or `any` (relaxed, development only) |
| `nxs.admission_ttl_seconds` | Lifetime of a minted admission token |
| `nxs.assisted_join_timeout_ms` | How long the provider waits for a host's answer before 504 |
| `nxs.proof_of_work_difficulty` | Register PoW difficulty (0 disables) |
| `nxs.bearer_tokens` / `admin_token` | Host authentication / admin API access |

See `testdata/nxs/wire-reference.md` for the protocol behavior Siglark implements.

## Development

```powershell
go test ./...            # protocol fixtures + flow + client signaling tests
go run ./cmd/nxsprobe -provider http://localhost:8080   # live protocol probe
```

## Roadmap

- Host-uploaded assertion material (provider never holds host private keys)
- PostgreSQL store, TLS/reverse-proxy examples, metrics

## License

[MPL-2.0](LICENSE).
