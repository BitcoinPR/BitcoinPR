# Tor & I2P Networking

BitcoinPR can run its peer-to-peer traffic over anonymity networks so that an
observer on the local network — a hostile ISP, a captive portal — cannot see
which Bitcoin peers the node talks to, or that it is running a node at all. Tor
is fully supported (outbound over SOCKS5 plus an inbound `.onion` hidden
service); I2P support is being layered on top of the same address plumbing.

> **Address-layer, not consensus.** These options only change *how* the node
> reaches peers and *which* networks it dials. Validation, relay policy, and the
> chain the node follows are identical regardless of transport. A node reachable
> only over Tor sees exactly the same blockchain as a clearnet node.

## Options

| Option | Default | Core | Effect |
|--------|---------|------|--------|
| `proxy` | — | — | SOCKS5 proxy (`host:port`) for **all** outbound connections, e.g. a Tor daemon at `127.0.0.1:9050`. `.onion` hostnames are resolved by the proxy, never locally. |
| `onion` | = `proxy` | — | SOCKS5 proxy used specifically for `.onion` targets, overriding `proxy` for Tor. |
| `onlynet` | all | all | Repeatable. Restrict outbound connections to `ipv4`, `ipv6`, `onion`, and/or `i2p`. `onlynet=onion` with a Tor proxy makes a Tor-only node. |
| `proxyrandomize` | `1` | `1` | Randomize SOCKS5 credentials per connection so Tor isolates each peer onto its own circuit (stream isolation). |
| `listenonion` | `1` | `1` | Create a v3 `.onion` hidden service via the Tor control port so the node is reachable inbound over Tor. |
| `torcontrol` | `127.0.0.1:9051` | same | Tor control port used for `listenonion`. |
| `torpassword` | — | — | Password for the Tor control port. When unset, cookie-file (SAFECOOKIE) authentication is used automatically. |

Each option is a CLI flag (`--proxy=127.0.0.1:9050`, `--onlynet=onion`; a bare
`--listenonion` means "on") and a `bitcoinpr.conf` key (`proxy=127.0.0.1:9050`).
CLI values win over the conf file. See `example.bitcoinpr.conf`.

## Reaching peers over Tor (outbound)

`proxy` routes outbound dials through a SOCKS5 proxy. For IP peers the proxy
opens the TCP connection; for `.onion` peers the 56-character v3 address is sent
to the proxy as a hostname, so Tor — not BitcoinPR — does the rendezvous. The
proxied stream is otherwise a normal connection: the BIP-324 v2 encrypted
transport and the v1 fallback both run over it unchanged.

`proxyrandomize` (on by default) sends a fresh random username/password to the
proxy for every connection. Tor treats each credential pair as a separate
identity and builds an independent circuit, so different peers cannot be
correlated to one another through a shared exit.

## Being reachable over Tor (inbound)

With `listenonion` enabled, BitcoinPR connects to the Tor **control port** at
startup and issues `ADD_ONION` to create an ephemeral v3 hidden service that
forwards inbound streams to the node's local P2P listener. The resulting
`.onion` address is:

- **advertised** to peers via BIP-155 `addrv2` gossip, so other nodes can find
  and dial it;
- **persisted**: the service's private key is written to
  `<datadir>/<network>/onion_v3_key` (owner-readable only) and reused on the
  next start, so the node keeps a stable `.onion` across restarts;
- **self-dial protected**: the node never dials its own advertised address.

Control-port authentication is negotiated automatically, preferring — in order —
password (`torpassword`), SAFECOOKIE (an HMAC-SHA256 challenge over Tor's cookie
file), plain cookie, then null auth. If the control port is unreachable or
authentication fails, the node logs one line and continues **without** an inbound
onion service; startup never fails because of Tor.

For the cookie methods the BitcoinPR process must be able to read Tor's
`control.authcookie` (typically by sharing Tor's group). A minimal `torrc`:

```
ControlPort 9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1
```

## A Tor-only node

```
proxy=127.0.0.1:9050
onlynet=onion
listenonion=1
```

With `onlynet=onion` the node dials only `.onion` peers and **skips clearnet DNS
seeding entirely** — a node that never wants its ISP to see a Bitcoin DNS lookup
gets that guarantee. A fresh Tor-only node bootstraps from the **built-in fixed
seeds** (mainnet only, generated from Bitcoin Core's
`contrib/seeds/nodes_main.txt`; see `bitcoinpr-p2p/data/nodes_main.txt`): when
the address book cannot supply enough dial candidates, a random subset of the
fixed seeds matching `-onlynet` is folded in — at startup and again (rate-limited
to every 10 minutes) from the peer-maintenance loop. Once a first peer is
reached, `addrv2` gossip fills the address book and the fixed seeds are no
longer consulted. `connect=<addr>.onion` still works to pin an explicit peer,
and on non-mainnet networks (which ship no fixed seeds) it remains the only
Tor-only bootstrap.

### IBD throughput over Tor

Onion-service circuits are slow (typically tens of KB/s each), so IBD speed is
roughly linear in the number of circuits. Two mitigations are built in when
`-onlynet` excludes every IP network:

- the outbound connection target is raised from 24 to 44;
- during deep IBD (block tip >10,000 behind the header tip), peers whose
  measured delivery rate falls far below the pool median are periodically
  disconnected. With `proxyrandomize` each redial draws a fresh Tor circuit,
  so the pool steadily accumulates fast circuits. The gate is relative — a
  uniformly slow pool evicts nobody.

## Verifying it works

`getnetworkinfo` reports per-network reachability and the node's own addresses:

```json
{
  "networks": [
    { "name": "onion", "reachable": true, "proxy": "127.0.0.1:9050",
      "proxy_randomize_credentials": true }
  ],
  "localaddresses": [
    { "address": "abcd…zad.onion", "port": 8333, "score": 1 }
  ]
}
```

`getpeerinfo` tags each peer with its network:

```json
{ "id": 3, "addr": "wxyz…qid.onion:8333", "network": "onion", "inbound": false }
```

The web dashboard's peer table shows the same `Net` column. Watching the log at
startup, a successful hidden service prints `Tor hidden service established`
with the `.onion` address.

## I2P

I2P is reached through a local router's **SAM v3 bridge** rather than a SOCKS5
proxy. Point BitcoinPR at the SAM port and it opens a STREAM session, dialing
peers with `STREAM CONNECT` and (by default) accepting inbound peers with a
`STREAM ACCEPT` loop.

| Option | Default | Effect |
|--------|---------|--------|
| `i2psam` | — | SAM bridge address (`host:port`), e.g. i2pd at `127.0.0.1:7656`. Unset disables I2P. |
| `i2pacceptincoming` | `1` (when `i2psam` set) | Accept inbound I2P connections via the SAM session. |

```
i2psam=127.0.0.1:7656
i2pacceptincoming=1
onlynet=i2p
```

The session's private destination is persisted to
`<datadir>/<network>/i2p_private_key`, so the node keeps a stable
`<52-char>.b32.i2p` address across restarts. That address is computed as
`base32(SHA-256(destination))`, advertised to peers via `addrv2` (exactly like
the `.onion`), and reported in `getnetworkinfo` `localaddresses`; I2P peers show
`"network": "i2p"` in `getpeerinfo` and the dashboard. As with Tor, a failed or
unreachable SAM bridge is logged and skipped — it never blocks startup — and
`onlynet=i2p` restricts the node to I2P-only peers (again skipping clearnet DNS).

Enable SAM in i2pd's `sam.conf` (`enabled = true`, default port 7656), or in
Java I2P via the SAM application bridge on the router console.
