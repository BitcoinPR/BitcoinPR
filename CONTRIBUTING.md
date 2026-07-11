# Contributing to BitcoinPR

## Overview

BitcoinPR is an experimental Bitcoin full-node implementation in Rust. The
project operates an open contributor model: anyone is welcome to contribute
via peer review, testing, and patches. Repository maintainers merge pull
requests; releases are cut from version branches by the lead maintainer.

> **Warning:** parts of this codebase enforce Bitcoin consensus rules. A bug
> in consensus code can fork a node off the network or destroy funds.
> Contributions touching consensus are held to a much higher review bar than
> anything else — see [Consensus and policy changes](#consensus-and-policy-changes).

## Communication

Development discussion happens on GitHub:

- **Issues** — bug reports, feature proposals, design discussion
- **Pull requests** — code review and patch discussion

For complex or controversial changes (anything touching consensus, P2P
behavior, or relay policy), open an issue describing the proposal *before*
writing code, so the concept can be ACKed or rejected cheaply.

## Contributor workflow

1. **Fork** the repository
2. **Create a topic branch** off `latest`
3. **Commit patches** — atomic, self-contained commits that each build and pass tests
4. **Push** to your fork
5. **Open a pull request** against `latest`

### Commit messages

This repository uses conventional-commit style:

```
type(scope): short imperative summary

Optional body explaining *why* the change is needed, not just what it
does. Wrap at ~72 characters. Reference issues with "refs #123" or
"fixes #123".
```

- **type**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`
- **scope**: the crate or subsystem touched — e.g. `core`, `p2p`, `sync`,
  `storage`, `rpc`, `mining`, `index`, `web`, `policy`, `script`
- Keep the summary line at or under ~50 characters where practical

Examples from the log:

```
feat(policy): add Knots-style relay-policy options
fix(sync): select sync peer at equal height so at-tip restarts complete instantly
docs: README + TODO + relay-policy doc for the Knots-style policy filters
```

## Areas of the codebase

Prefix your PR title (or commit scope) with the affected component:

| Area | Code |
|------|------|
| Consensus / validation / script | `bitcoinpr-core/` |
| Mempool & relay policy | `bitcoinpr-core/` (see `docs/relay-policy.md`) |
| P2P networking & sync | `bitcoinpr-p2p/` |
| Storage / UTXO / pruning | `bitcoinpr-storage/` |
| JSON-RPC | `bitcoinpr-rpc/` |
| Mining (Stratum V1/V2) | `bitcoinpr-mining/` |
| Electrum / scripthash index | `bitcoinpr-index/` |
| Web explorer | `bitcoinpr-web/` |
| Daemon / CLI | `bitcoinpr/` |
| Docs | `docs/`, `README.md` |
| Scripts and tools | `scripts/`, `contrib/`, `docker/` |
| Tests | unit tests in-crate, interop suite in `scripts/` |

## Quality gate

Every change must pass the static gate **before** review:

```sh
scripts/gate.sh
```

which runs:

1. `cargo fmt --check`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
3. `cargo audit` — dependency advisory scan
4. `cargo machete` — unused-dependency check
5. `cargo test --workspace --all-features`

Note the `--all-features` flags: release images build with `--features full`,
so feature-gated code (web, indexing) must compile and pass clippy/tests too.
A featureless workspace build will not catch breakage there.

### Interop suite

Changes to consensus, P2P, mempool/relay, mining, or storage must also pass
the Docker interop suite, which runs BitcoinPR against Bitcoin Core and Knots
nodes on a regtest cluster:

```sh
scripts/interop-test.sh
```

See `docs/interop-cluster.md` for cluster setup. All tests must pass; a PR
that turns the suite red will not be merged. If a test is flaky or fails for
environmental reasons (long-lived cluster aging, subsidy exhaustion), say so
in the PR and show a passing run against a fresh cluster.

## Testing

- **Unit tests** live alongside the code they test. Bug fixes should include
  a regression test that fails without the fix.
- **Property tests** (proptest) cover low-level primitives (`u256`, merkle);
  extend them when touching those areas.
- **Fuzz targets** live in `fuzz/`; consider adding one when introducing new
  parsers or decoders.
- **Interop tests** are the ground truth for network-visible behavior —
  if Core and Knots disagree with BitcoinPR, BitcoinPR is wrong.

## Consensus and policy changes

- **Consensus code** (`bitcoinpr-core` validation, script interpreter, UTXO
  rules) must match Bitcoin Core's behavior exactly, including its quirks.
  Divergence — even "fixing" an apparent bug — can fork the node off the
  network. Such changes require a clear reference to the corresponding
  Core behavior or BIP, and thorough interop verification.
- **Relay policy** (mempool standardness, datacarrier, parasite/token
  filters) is intentionally stricter than Core's defaults but must remain
  *policy-only*: a filtered transaction appearing in a block must still
  validate. The ground rules for adding policy filters are documented in
  `docs/relay-policy.md` — read them before proposing a new filter.

## Pull request guidelines

- The body should clearly describe **what** the patch does and **why**,
  with links to any prior issue discussion.
- Keep PRs focused: one logical change per PR. Unrelated refactors or
  formatting drift belong in separate commits or separate PRs.
- Use GitHub **draft PRs** for work in progress.
- New features must come with tests and, where behavior is user-visible,
  documentation (README feature list, `docs/`, `example.bitcoinpr.conf`).

### Peer review

Reviewers use Bitcoin-style review language:

- **ACK** — I have tested the change and agree it should be merged
- **utACK** — I have reviewed the code and it looks correct, but did not test it
- **Concept ACK** — I agree with the goal, without judging the implementation
- **NACK** — I disagree; must be accompanied by technical justification
- **Nit** — trivial, non-blocking issue

### Squashing

Maintainers may ask you to squash fixup commits before merge:

```sh
git checkout your_branch_name
git rebase -i HEAD~n   # n = number of commits to squash
git push --force-with-lease
```

## Branches and releases

- **`latest`** — the default branch; all PRs target it
- **Version branches** (e.g. `0.1.110`) — cut from `latest` for each
  release; only receive backported fixes

## Copyright

By contributing, you agree to license your work under the MIT license
(see `Cargo.toml`), unless explicitly stated otherwise in the commit.
