# GoldAccountManager

A plug-and-play account management toolkit written in Go. Drop in authentication, user profiles, roles, sessions and admin tools, then self-host or customize it to fit your product. Open source, dependency-light (standard library only), and built to be forked, so you own your user data instead of renting it.

## Two modes, one identity

| | Packet mode (serverless) | Server mode |
| --- | --- | --- |
| Where the account lives | A signed JSON file the user carries | The packet plus a small Go service |
| Server needed | No | Yes, a thin one |
| Best for | Single-player tools: weather, calculators, planners, trackers | Apps with a shared pool of people: dating, social, marketplaces |
| Login | App verifies the packet locally | Challenge-response, no passwords |
| Extras | User stores it on their device or Drive | Public profiles, roles, sessions, admin tools |

Both modes use the same identity, so a user can start with a packet and register it with a server later.

## Packets

A packet is a portable account. It holds a user's public identity, profile and settings, signed with a key that never leaves their device. Think of it as a receipt you carry that any app can check, instead of an account each app has to create and store.

```go
id, _ := packet.NewIdentity()
p, _ := id.NewPacket(
    map[string]any{"name": "Nathan"},      // profile
    map[string]any{"units": "imperial"},   // settings
)
data, _ := p.Encode()                      // save anywhere: device, Drive, file

got, err := packet.Decode(data)            // verifies the signature
```

Editing a packet without the key breaks its signature, so call `id.Sign(p)` after any change.

## Server mode

```go
srv := server.New(server.NewMemoryStore())
http.ListenAndServe(":8080", srv.Handler())
```

- `POST /register` with a packet
- `POST /challenge` with the account id, which returns a nonce
- `POST /login` with the signed nonce, which returns a session token

Use `srv.Authenticate(token)` in your own handlers and `server.RequireRole` for admin routes. The memory store is for development. Implement `server.Store` for your database.

## Status

Early skeleton. Packet signing, verification and challenge-response login work and are tested. Persistence, rate limiting, recovery flows and admin tools are still to build. See [docs/DESIGN.md](docs/DESIGN.md) for the design, security notes and open items.

## Planned users

ClearSky, Payout Lab and other serverless tools in packet mode, and Pasta in server mode.

## License

See [LICENSE](LICENSE).
