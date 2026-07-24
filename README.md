# slim-m-relay

The push relay for slim-m.

slim-m is open source, so anyone can self-host the server.
But waking a mobile device is the one part a self-hoster cannot fully do themselves: the published apps embed the maintainer's Apple and Google push credentials, and those credentials are master keys that can push to any slim-m device on any server.
Handing them out directly is not an option.

This relay is the fix.
The maintainer runs one instance that holds the two credentials: an APNs `.p8` token key for iOS and a Firebase service account for Android.
A self-hosted slim-m server registers with it once on first boot, gets a scoped, revocable key, and from then on POSTs its wake-up pushes to the relay instead of straight to Apple or Google.
So a host running the published apps gets working push on both platforms, and nobody but the maintainer ever holds either credential.

The relay is deliberately minimal.
It is not the messaging backend, and it is not part of slim-m's end-to-end encryption.
The home server encrypts every payload before it ever reaches the relay.
The relay forwards that opaque ciphertext, plus a coarse `kind` (`message`, `mention`, `call`, or `wake`), to whichever provider the target device uses.
It never encrypts, decrypts, or inspects payload content, and it never logs it either.

## What the relay sees

Only what it needs to route and wake a device: a platform (`ios` or `android`), a device token, a coarse kind, and an opaque, already-encrypted payload blob.
It never sees message text, sender identity, group membership, or anything else the home server encrypted.
It does not log tokens or payload content, only counts and error codes.

## How it works

1. A slim-m server boots with a relay URL configured.
2. If it has no key yet, it calls `POST /v1/register` with its public URL.
   The relay mints a key (registration is per-IP rate-limited) and returns it once, recording the public URL as an admin label.
   The server stores the key and reuses it forever after.
3. When something happens worth waking a device for, the server calls `POST /v1/send` with its key and a batch of `{platform, token, kind, payload}`.
   The relay forwards each message to APNs or FCM depending on its platform, and returns a per-token result so the server can prune tokens the provider reports as dead.

Keys are stored as SHA-256 hashes in a small SQLite file, so a leak of the database yields nothing usable.
Registration is rate-limited per IP and sending is rate-limited per key.
A misbehaving server can be cut off with `POST /admin/keys/{id}/revoke`.

### Token-to-key binding

Because device tokens are opaque strings that a server could in principle send to any registered token, the relay adds one hardening rule beyond scoped keys: the first key to send to a given `(platform, token)` pair becomes that token's owner, permanently, in the same SQLite store.
Every later send to that token must come from the same key.
A send from a different key for a token it does not own is rejected with `forbidden`, and never reaches APNs or FCM.
This keeps one self-hosted server from harassing another server's devices, even if it somehow obtained their tokens.

## API

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/v1/register` | none (IP rate-limited) | Mint a key. Optional body `{"publicUrl": "..."}` is recorded, unverified, as an admin label. |
| `POST` | `/v1/send` | `Authorization: Bearer <key>` | Forward `{"messages": [{"platform","token","kind","payload"}]}` to APNs or FCM by platform. Returns `{"results": [{"token","status"}]}` where status is `delivered`, `unregistered`, `forbidden`, or `error`. |
| `GET` | `/healthz` | none | Liveness. |
| `GET` | `/admin/keys` | `Authorization: Bearer <admin token>` | List issued keys (metadata only). |
| `POST` | `/admin/keys/{id}/revoke` | `Authorization: Bearer <admin token>` | Revoke a key. |

Admin endpoints are only mounted when `RELAY_ADMIN_TOKEN` is set.

`platform` is `ios` or `android`.
`kind` is `message`, `mention`, `call`, or `wake`.
`payload` is the home server's already-encrypted blob, forwarded byte-for-byte; the relay never inspects it.

## Running it

You need the credentials for the project the published apps are built against: a Firebase service-account JSON for Android, and an APNs `.p8` token key (with its key id, team id, and the app's bundle id) for iOS.
Either platform can be left unconfigured; sends to that platform fail clearly instead of the relay refusing to start.

```bash
cp .env.example .env
# fill in RELAY_ADMIN_TOKEN and whichever provider credentials you have
```

Then run the binary directly, or build the Docker image and mount your credential files and the `/data` volume yourself:

```bash
docker build -t slim-m-relay .
docker run -d \
  -p 8090:8090 \
  -v $(pwd)/data:/data \
  -v $(pwd)/fcm-service-account.json:/run/secrets/fcm-service-account.json:ro \
  -v $(pwd)/apns-auth-key.p8:/run/secrets/apns-auth-key.p8:ro \
  --env-file .env \
  slim-m-relay
```

Put the relay behind whatever reverse proxy you already run (Caddy, Traefik, nginx).
The relay reads the client IP from `X-Forwarded-For`, which a trusted proxy sets, so per-IP registration limits stay accurate.
The `/data` volume holds the SQLite key store; back it up, since losing it means every registered server re-registers on its next boot, and every device token re-establishes its binding to whichever server sends to it first.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_PORT` | `8090` | TCP port the relay listens on. |
| `RELAY_DB_PATH` | `/data/relay.db` | SQLite key store path. |
| `RELAY_ADMIN_TOKEN` | *(empty)* | Guards `/admin`. Empty disables those endpoints. |
| `RELAY_FCM_CREDENTIALS_FILE` | *(empty)* | Path to the Firebase service-account JSON. Empty disables Android sends. |
| `RELAY_APNS_KEY_PATH` | *(empty)* | Path to the APNs `.p8` token key. |
| `RELAY_APNS_KEY_ID` | *(empty)* | The `.p8` key's 10-character key id. |
| `RELAY_APNS_TEAM_ID` | *(empty)* | Apple Developer Team ID. |
| `RELAY_APNS_BUNDLE_ID` | *(empty)* | App bundle id, used as the APNs topic. |
| `RELAY_APNS_PRODUCTION` | `true` | `true` for APNs' production gateway, `false` for the sandbox gateway. All four `RELAY_APNS_*` credential fields are required together; if any is empty, iOS sends fail clearly. |
| `RELAY_REGISTER_PER_HOUR` | `5` | Per-IP registration rate. |
| `RELAY_REGISTER_BURST` | `3` | Per-IP registration burst. |
| `RELAY_SEND_PER_MINUTE` | `120` | Per-key send rate. |
| `RELAY_SEND_BURST` | `60` | Per-key send burst. |
| `RELAY_MAX_MESSAGES` | `500` | Device tokens allowed in one `/v1/send`. |

## Development

```bash
go test ./...
go build ./cmd/relay
```

Go 1.26, no CGO (the SQLite driver is pure Go), single static binary.
