# Siglark + PowerNukkitX in Docker

Two containers: PNX registers with Siglark as an NXS host, and Bedrock clients
reach PNX through it instead of a hosted signaling service.

```
client ──TCP──> siglark:8080        (discovery, admission, assisted join)
   └────────UDP──> pnx:19132         (NetherNet media, straight to the server)
                    │
                    └──TCP──> siglark:8080 (register, heartbeat, control WS)
```

Both containers share the `pnx-data` volume: PNX generates `keys/identity.pem`
on first boot, and Siglark signs the server identity assertion in each answer
with that key. The key must stay stable — replacing it makes every returning
player accept the trust prompt again.

## Before you start

You need two addresses that are **not** container names:

- `SERVER_ADDRESS` — what players type into the client, e.g. `192.168.1.10` or
  `play.example.com`. This becomes `hosts[].host` in `siglark.yaml`.
- The same machine's address must also reach **UDP 19132** from where players
  are. On a LAN that is automatic; from the internet you must forward the port.

Edit `siglark.yaml` and replace `192.168.1.10` with `SERVER_ADDRESS`.

## 1. Start PNX once to generate its configuration

```sh
docker compose up -d pnx
docker compose cp pnx:/data/pnx.yml ./pnx.yml
```

PNX exits early if `pnx.yml` does not exist yet on some versions; if the copy
fails, run `docker compose logs pnx` and check that the container created
`/data/pnx.yml` before it stopped.

## 2. Point PNX at Siglark

In the generated `pnx.yml`, under `pnx.settings.network.nethernet`, set the
values below. Key spelling follows the file Okaeri generated; edit the keys
that are actually there, the names below are the meanings.

| Setting | Value |
|---|---|
| signaling mode | `nxs` |
| `nxs.endpoint` | `http://siglark:8080` |
| `nxs.token` | empty (Siglark allows anonymous registration) |
| `nxs.advertise-addresses` | `SERVER_ADDRESS:19132` |
| `nxs.advanced.assisted-joins` | `true` — required, Siglark serves joins this way |
| `nxs.advanced.connection-checks` | `false` if joins fail with a health-check error |
| `nxs.advanced.deregister-on-shutdown` | `true` (optional) |
| `identity-file` | `keys/identity.pem` (the default) |
| `identity-domain` | `Siglark-SelfhostNXS` |

Copy it back and restart:

```sh
docker compose cp ./pnx.yml pnx:/data/pnx.yml
docker compose restart pnx
```

## 3. Start Siglark and read the registration ID

```sh
docker compose up -d siglark
docker compose logs -f siglark   # wait for "waiting for PNX to generate keys/identity.pem" to clear
curl -s -H "Authorization: Bearer change-me" \
  http://127.0.0.1:8080/v1/admin/registrations
```

The response contains `registrationId` (PNX also logs it as
`Provider instance registered: inst_...`).

## 4. Map the address and restart Siglark

Put that ID into `siglark.yaml`:

```yaml
hosts:
  - host: "192.168.1.10"          # SERVER_ADDRESS
    registration_id: "reg_..."
    identity_pem: "/pnx/keys/identity.pem"
    identity_domain: "Siglark-SelfhostNXS"
```

```sh
docker compose restart siglark
```

## 5. Connect

Add `SERVER_ADDRESS:8080` in the Bedrock client. The first join may show a
trust prompt for `Siglark-SelfhostNXS`; accepting it pins the server identity
for later joins.

## Things that bite

- **Registration IDs change.** If the `pnx-data` volume is deleted, or the
  lease expires and PNX re-registers, the ID changes. Update `siglark.yaml`
  and restart Siglark. `TODO: auto-map registrations to hosts` is the planned
  fix.
- **`hosts[].host` is matched against the HTTP Host header**, ignoring the
  port. It must be what players type, not `siglark` or `localhost`.
- **`provider_origin` is not the player-facing address.** It is the origin
  PNX uses (`http://siglark:8080`), and it is what signatures are bound to.
- **UDP 19132 must be reachable directly.** Signaling gets the client a
  ticket; the media path is peer-to-peer to PNX.
- **Keep `pnx-data`.** It holds both `keys/identity.pem` and the world data.
