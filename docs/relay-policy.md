# Relay Policy Filters (Knots-style)

BitcoinPR ships a set of configurable relay-policy filters modeled on Bitcoin
Knots. They control which transactions this node **accepts into its mempool,
relays to peers, and includes in its own block templates** — nothing more.

> **Policy, never consensus.** Blocks mined by other nodes that contain
> filtered transactions are validated and accepted normally. Running any
> combination of these options can never fork the node off the network. This
> was verified live on the interop cluster: an Omni-marked transaction was
> rejected by BitcoinPR over both RPC and P2P, then mined by Bitcoin Core into
> a block that BitcoinPR accepted without complaint.

## Options

| Option | Default | Core | Knots | Effect when filtering |
|--------|---------|------|-------|-----------------------|
| `datacarrier` | `1` | `1` | `1` | `0` rejects every transaction with an OP_RETURN output |
| `datacarriersize` | `83` | `83` | `42` | Max OP_RETURN script size in bytes, including the OP_RETURN opcode. Ignored when `datacarrier=0` |
| `permitbaremultisig` | `0` | `1` | `0` | `0` rejects bare (non-P2SH) `m-of-n OP_CHECKMULTISIG` outputs |
| `rejectparasites` | `1` | — | `1` | `1` rejects transactions carrying an inscription envelope in a tapscript witness |
| `rejecttokens` | `1` | — | `0` | `1` rejects transactions carrying a recognized token-protocol marker |

Notes on the defaults:

- `permitbaremultisig=0` matches Knots, not Core. Bare multisig is the
  data-embedding vector used by Stamps/SRC-20: the "pubkeys" are arbitrary
  data, the outputs can never be spent, and every one of them bloats the UTXO
  set forever.
- `rejecttokens=1` is **stricter than Knots** (which defaults to `0`). This is
  a deliberate operator choice for this implementation; opt out with
  `rejecttokens=0`.

Each option is available as a CLI flag (`--rejecttokens=0`, `--datacarrier 0`;
a bare boolean flag such as `--rejectparasites` means "on") and as a
`bitcoinpr.conf` key (`rejecttokens=0` — the conf parser requires `key=value`,
so a bare `rejecttokens` line is ignored). CLI values win over the conf file;
unset options keep the defaults above. See `example.bitcoinpr.conf`.

At startup the node logs an info line for any filter set to a non-default
value. Individual rejections are logged at `debug` level with the txid and the
specific rule, e.g.:

```
tx rejected: invalid transaction: token: tx 4256e9… carries a omni marker (rejecttokens=1)
```

## Where enforcement happens

All rules run in `check_relay_policy` (`bitcoinpr-core/src/mempool.rs`), called
from `Mempool::accept`. That single choke point covers every path into the
mempool, and therefore:

- **RPC** — `sendrawtransaction` returns the rejection reason to the caller.
- **P2P relay** — transactions announced by peers are rejected on arrival and
  never re-relayed.
- **Mining** — block templates (`getblocktemplate` and the Stratum gateway)
  are built from the mempool, so filtered transactions never appear in blocks
  this node mines. No mining-side code is involved.

Block validation (`connect_block`) does **not** run any of these checks.

## Detection details

Pattern detection lives in `bitcoinpr-core/src/script.rs` next to the BIP-110
helpers, deliberately isolated so the pattern table is a one-module concern.

### Output rules (`check_output_policy`)

- `datacarrier=0`: any output whose scriptPubKey `is_op_return()` is rejected.
- `datacarriersize`: OP_RETURN scripts longer than the limit are rejected.
- `permitbaremultisig=0`: any output matching rust-bitcoin's
  `Script::is_multisig()` (bare `m-of-n CHECKMULTISIG`) is rejected.
- Dust and the BIP-110 output rules (when RDTS is active) run in the same
  loop; BIP-110's 34/83-byte output limits overlap substantially with
  `datacarrier` filtering while the softfork is active.

### Parasites: inscription envelopes (`tx_first_inscription_input`)

An *inscription envelope* is the ordinals data-embedding pattern inside a
taproot leaf script:

```
OP_FALSE OP_IF <push> <push> … OP_ENDIF
```

The empty push makes the IF branch dead code, so arbitrary data rides the
witness discount without ever executing. Detection:

1. **Recognize a script-path spend structurally.** The mempool has no prevouts
   at this point in `accept`, so taproot script-path is identified by witness
   shape: after excluding a BIP 341 annex (last element starting `0x50` when
   ≥ 2 elements remain), a script-path witness is `[args…, leaf script,
   control block]` where the control block is `33 + 32m` bytes with leaf
   version `0xc0`/`0xc1`. Key-path spends, P2WPKH, and P2WSH witnesses do not
   match this shape.
2. **Scan the leaf script** for an empty push immediately followed by `OP_IF`.

This is the same heuristic level Knots applies for relay filtering. A
transaction crafted to *look* like a script-path spend without being one would
be policy-rejected — an acceptable false positive for relay purposes, since
such a transaction is deliberately unusual.

### Tokens: protocol markers (`tx_token_protocol`)

The token pattern table, in detection order:

| Protocol | Marker |
|----------|--------|
| **Runes** | OP_RETURN whose second byte is `OP_13` (`0x6a 0x5d` — the runestone magic) |
| **Omni Layer** | first OP_RETURN data push begins with ASCII `omni` |
| **Counterparty** | first OP_RETURN data push begins with ASCII `CNTRPRTY` |
| **BRC-20** | inscription envelope whose concatenated payload contains `brc-20` (the JSON `"p":"brc-20"` protocol tag) |

BRC-20 detection is independent of `rejectparasites`: with parasites allowed
but tokens rejected, a plain image inscription relays while a BRC-20 mint does
not.

## Interop expectations

Peers running Bitcoin Core (or any node with laxer policy) will hold
transactions in their mempools that this node refuses. That mempool divergence
is normal and harmless: the transactions confirm once *someone* mines them,
and this node accepts the containing block. The full interop suite (Core,
Knots, btcd, libbitcoin) passes 18/18 with all filters at their defaults.

## Future adjustments: extending the pattern table

Token and parasite protocols churn; the table above reflects what existed when
this was written. Ground rules for changes:

1. **Keep all detection in `script.rs`.** Add a marker check inside
   `tx_token_protocol` (or a structural detector beside
   `tx_first_inscription_input`) and return a short lowercase protocol name —
   the name appears verbatim in reject messages and logs.
2. **Add a unit test per pattern** — a positive case and a near-miss negative
   (see `test_token_protocol_detection`). The reject-path test belongs in
   `mempool.rs` (`test_parasite_and_token_relay_policy`) only if the new rule
   changes *which* filter flag governs it.
3. **Stay policy-only.** Never plumb these checks into `connect_block` or any
   block-validation path. A pattern-table mistake must only ever cost relay,
   not consensus.
4. **Prefer precise magic over substring heuristics.** Prefix/opcode markers
   (runestone `OP_13`, `CNTRPRTY`) are cheap and precise. Payload substring
   scans (BRC-20) are acceptable inside an already-identified envelope, where
   arbitrary data has already been smuggled deliberately — not on ordinary
   script fields, where false positives would hit legitimate traffic.
5. **Track Knots.** Knots' `-rejectparasites`/`-rejecttokens` definitions
   evolve per release; when syncing with a new Knots release, diff their
   policy changes and mirror what fits. Candidates already on the radar:
   Stamps/SRC-20 P2WSH variants (the bare-multisig form is already blocked by
   `permitbaremultisig=0`), Atomicals/ARC-20, and new runestone versions —
   Runes detection keys on the `OP_13` magic, so protocol-internal versioning
   is already covered.
6. **Changing a default is a behavior change.** Call it out in the commit
   message, update this document, `example.bitcoinpr.conf`, the README table,
   and `test_relay_policy_defaults`, and run the interop suite before merging.
