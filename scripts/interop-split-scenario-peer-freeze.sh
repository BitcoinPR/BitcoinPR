#!/usr/bin/env bash
#
# BIP-110 split scenario: connectivity disruption WITHOUT a process restart.
#
# Every other split scenario that tests recovery does it via a full node
# restart (docker restart split-bitcoinpr) — that exercises SplitMonitor's
# boot-time `load_persisted_rivals()` path, rebuilding everything from disk.
# This scenario deliberately avoids restarting the process at all: it uses
# `docker pause` to freeze split-bitcoinpr in place (a cgroup SIGSTOP-style
# freeze — the process, its in-memory HeaderSync/SplitMonitor state, and its
# open peer socket are all preserved exactly, nothing reloads from disk)
# while Core keeps mining, unseen, on the rival branch. On `docker unpause`
# the live (never-restarted) HeaderSync must notice the backlog and catch up
# via ordinary getheaders resync — a genuinely different code path from the
# persistence-across-restart tests.
#
# Honesty note: this models the node's own process stalling (descheduled,
# a long GC/disk pause, etc.) rather than a true network-level partition —
# a real partition that also keeps RPC reachable on both sides would need
# host-level firewall rules targeting just the P2P port between the two
# containers, which is out of scope for a self-contained test script. The
# pause/unpause approach is fully self-contained (touches only containers
# this test created) and still exercises the resync-without-reboot path.
#
# Usage: ./scripts/interop-split-scenario-peer-freeze.sh [--keep]

set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/lib/split-helpers.sh

KEEP=0
for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=1 ;;
        *) echo "unknown arg: $arg"; exit 2 ;;
    esac
done

setup_split

rival_h=$FORGED_HEIGHT
ours_h=$BASELINE

step "Grow the rival lead a bit before freezing (known-good baseline)"
core_mine 5
rival_h=$((rival_h + 5))
wait_split_match "$rival_h" "$ours_h" 90 || fail "pre-freeze: monitor did not settle at rival=$rival_h ours=$ours_h"
[[ "$ARMED" == "True" ]] || fail "pre-freeze: armed='$ARMED' — expected True at deficit $DEFICIT"
info "pre-freeze: rival=$rival_h ours=$ours_h deficit=$DEFICIT armed=$ARMED"

step "Freeze split-bitcoinpr (docker pause) — process stalls, no restart"
docker pause split-bitcoinpr >/dev/null
FROZEN_CHECK=$(rpcurl "$PR_RPC" getblockcount "[]" 5 | result_of) || true
[[ -z "$FROZEN_CHECK" ]] || fail "split-bitcoinpr answered RPC while paused ('$FROZEN_CHECK') — pause did not take effect"
info "confirmed frozen: RPC unreachable while paused"

step "Core mines on, unseen, while split-bitcoinpr is frozen"
core_mine 20
rival_h=$((rival_h + 20))
info "Core advanced to $rival_h while split-bitcoinpr was frozen"

step "Thaw split-bitcoinpr (docker unpause) — no restart, same process"
docker unpause split-bitcoinpr >/dev/null
wait_rpc "$PR_RPC" 60 || fail "split-bitcoinpr RPC did not come back after unpause"
info "RPC responsive immediately after thaw"

step "Confirm the live (never-restarted) node resyncs the full backlog"
wait_split_match "$rival_h" "$ours_h" 90 || fail "post-thaw: monitor did not catch up to rival=$rival_h ours=$ours_h"
[[ "$FORK_H" == "$BASELINE" ]] || fail "post-thaw: fork_height $FORK_H != $BASELINE"
[[ "$ARMED" == "True" ]] || fail "post-thaw: armed='$ARMED' — expected True at deficit $DEFICIT"
pr_h_check=$(pr getblockcount | result_of)
[[ "$pr_h_check" == "$BASELINE" ]] || fail "post-thaw: our own validated height $pr_h_check != $BASELINE — the freeze must not have touched our own chain"
info "post-thaw: rival=$rival_h ours=$ours_h deficit=$DEFICIT armed=$ARMED — full backlog resynced with no restart, our own chain untouched"

step "Confirm mining still works post-thaw (not just RPC liveness)"
pr_mine 1
ours_h=$((ours_h + 1))
wait_split_match "$rival_h" "$ours_h" 60 || fail "post-thaw mining: monitor did not settle at rival=$rival_h ours=$ours_h"
(( DEFICIT == rival_h - ours_h )) || fail "post-thaw mining: deficit $DEFICIT != $((rival_h - ours_h))"
info "post-thaw mining: ours=$ours_h deficit=$DEFICIT — block production pipeline healthy after the freeze/thaw cycle"

step "PASS"
teardown_split "$KEEP"
exit 0
