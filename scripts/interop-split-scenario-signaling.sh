#!/usr/bin/env bash
#
# BIP-110 split scenario: the REAL mandatory-signaling state machine.
#
# Every other interop-split-scenario-*.sh (and the base interop-split-test.sh)
# drives BIP-110 via the --bip110height FIXED-mode override, which skips
# signaling entirely and is ACTIVE from a hardcoded height. This scenario
# instead drives the actual DEFINED -> STARTED -> LOCKED_IN -> ACTIVE state
# machine via --bip110signaling (bitcoinpr-core/src/bip110.rs), on a fixture
# scaled down 126x from mainnet's real deployment (bips.dev/110):
#
#                        mainnet          this fixture (period 16)
#   period               2016             16
#   threshold            1109 (55%)       100 (unreachable — mirrors the
#                                          real world's <1% signaling)
#   mandatory window     961632-963647    96-111
#   lock-in floor        963648           112
#   activation           965664           128
#
# split-signaling-core is stock Bitcoin Core — it has no notion of BIP-110
# bit 4, so it never signals. The scenario proves the three milestones fire
# at exactly the right heights:
#
#   Phase A  height < 96   (mainnet: < 961632) — STARTED but outside the
#            window: Core's ordinary non-signaling blocks are fine.
#   Phase B  height 96     (mainnet: 961632)   — the window opens: Core mines
#            one more ordinary (non-signaling) block and our node holds —
#            the FIRST point the chains can diverge, exactly as described.
#   Phase C  our node mines its own signaling chain through the window and
#            past the lock-in floor (112); once it out-works Core's 1-block
#            fork, Core reorgs onto it via plain fork choice (no capitulation
#            needed — Core's block was never invalid by Core's own rules).
#   Phase D  height 121 (LOCKED_IN, past the window) — Core mines a plain
#            non-signaling block and it's accepted: the mandatory-signaling
#            rule only applies while STARTED, proving the window's close.
#   Phase E  height 128    (mainnet: 965664)   — ACTIVE: an RDTS rule
#            (oversized OP_RETURN) now gets rejected, reusing the same
#            enforcement mechanism (and invalid-reason "consensus-bip110",
#            distinct from Phase B's "mandatory-signaling") the other seven
#            scenarios already exercise from the fixed-mode side.
#
# Usage: ./scripts/interop-split-scenario-signaling.sh [--keep]
#   --keep   leave the cluster running after a pass (implied on failure)

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

# This fixture uses its own compose file, project, containers, and network —
# retarget the lib's globals. Its RPC/wait/mine/teardown helpers read these
# at call time, so overriding them here is enough to reuse that code.
COMPOSE=(docker compose -p bitcoinpr-split-signaling -f docker-compose.split-signaling.yml)

# Deployment schedule (period 16 — see docker-compose.split-signaling.yml).
WINDOW_LO=96
WINDOW_HI=111
LOCKIN_FLOOR=112
LOCKED_IN_CHECK_HEIGHT=120   # inside (112,127), comfortably past the floor
ACTIVATION=128

step "Start signaling-mode split cluster (real --bip110signaling deployment)"
start_cluster

core createwallet '["split"]' >/dev/null 2>&1 || core loadwallet '["split"]' >/dev/null 2>&1 || true
CORE_ADDR=$(core getnewaddress | result_of)
[[ -n "$CORE_ADDR" ]] || fail "could not get a Core wallet address"

mode=$(pr getchainsplitinfo | jget "['bip110']['mode']")
[[ "$mode" == "signaling" ]] || fail "bip110 mode '$mode' — expected 'signaling'"
info "Cluster up, bip110 mode=$mode"

step "Phase A: sync to height $((WINDOW_LO - 1)) (STARTED, outside the mandatory window)"
core_mine $((WINDOW_LO - 1))
wait_height "$PR_RPC" $((WINDOW_LO - 1)) 90 || fail "did not reach height $((WINDOW_LO - 1))"
pr_tip=$(pr getbestblockhash | result_of)
core_tip=$(core getbestblockhash | result_of)
[[ "$pr_tip" == "$core_tip" ]] || fail "tips disagree before the mandatory window ($pr_tip vs $core_tip)"
info "Both nodes at height $((WINDOW_LO - 1)), tips agree"

step "Phase B: mandatory window opens at $WINDOW_LO — Core mines a non-signaling block"
core_mine 1
sleep 10
pr_h=$(pr getblockcount | result_of)
[[ "$pr_h" == "$((WINDOW_LO - 1))" ]] || fail "split-signaling-bitcoinpr advanced to $pr_h — expected to hold at $((WINDOW_LO - 1))"
core_h=$(core getblockcount | result_of)
[[ "$core_h" == "$WINDOW_LO" ]] || fail "Core height $core_h — expected $WINDOW_LO"
info "Held at $((WINDOW_LO - 1)) while Core advanced alone to $WINDOW_LO — diverged exactly at the window's opening height"

wait_split_match "$WINDOW_LO" "$((WINDOW_LO - 1))" 90 || fail "monitor did not surface the mandatory-signaling split"
reason=$(echo "$SPLIT_JSON" | jget "['split']['rival_first_invalid']['reason']")
inv_h=$(echo "$SPLIT_JSON" | jget "['split']['rival_first_invalid']['height']")
[[ "$reason" == "mandatory-signaling" ]] || fail "rival_first_invalid reason '$reason' — expected 'mandatory-signaling'"
[[ "$inv_h" == "$WINDOW_LO" ]] || fail "rival_first_invalid height '$inv_h' — expected $WINDOW_LO"
info "getchainsplitinfo: rival=$RIVAL_H ours=$OURS_H first_invalid=$inv_h reason=$reason"

step "Phase C: our node mines its own signaling chain to height $LOCKED_IN_CHECK_HEIGHT (past lock-in floor $LOCKIN_FLOOR)"
pr_mine $((LOCKED_IN_CHECK_HEIGHT - (WINDOW_LO - 1)))
wait_height "$PR_RPC" "$LOCKED_IN_CHECK_HEIGHT" 90 || fail "did not reach $LOCKED_IN_CHECK_HEIGHT"
# Core's 1-block non-signaling fork is now out-worked by our longer signaling
# chain — plain fork choice reorgs Core onto it. Nothing about Core's block
# was invalid by Core's own rules, so this is an ordinary reorg, not a
# capitulation.
wait_height "$CORE_RPC" "$LOCKED_IN_CHECK_HEIGHT" 90 || fail "Core did not reorg onto our chain"
pr_tip=$(pr getbestblockhash | result_of)
core_tip=$(core getbestblockhash | result_of)
[[ "$pr_tip" == "$core_tip" ]] || fail "tips disagree after Core's reorg ($pr_tip vs $core_tip)"
info "Converged at $LOCKED_IN_CHECK_HEIGHT ($pr_tip) — Core reorged onto the signaling chain"

step "Phase D: height $((LOCKED_IN_CHECK_HEIGHT + 1)) (LOCKED_IN, past the window) — Core's non-signaling block is now fine"
core_mine 1
wait_height "$PR_RPC" $((LOCKED_IN_CHECK_HEIGHT + 1)) 60 || fail "non-signaling block past the window was rejected — mandatory-signaling rule leaked past height $WINDOW_HI"
pr_tip=$(pr getbestblockhash | result_of)
core_tip=$(core getbestblockhash | result_of)
[[ "$pr_tip" == "$core_tip" ]] || fail "tips disagree at $((LOCKED_IN_CHECK_HEIGHT + 1)) ($pr_tip vs $core_tip)"
info "Non-signaling block accepted at $((LOCKED_IN_CHECK_HEIGHT + 1)) — mandatory window is correctly closed once LOCKED_IN"

step "Phase E: advance to activation height $ACTIVATION"
core_mine $((ACTIVATION - LOCKED_IN_CHECK_HEIGHT - 1))
wait_height "$PR_RPC" "$ACTIVATION" 90 || fail "did not reach activation height $ACTIVATION"
wait_height "$CORE_RPC" "$ACTIVATION" 90 || fail "Core did not reach $ACTIVATION"
info "Both nodes at $ACTIVATION"

step "Confirm ACTIVE: an RDTS rule (oversized OP_RETURN) is now enforced"
forge_invalid_block "aa" "$ACTIVATION"
wait_split_match "$FORGED_HEIGHT" "$ACTIVATION" 90 || fail "monitor did not surface the post-activation split"
reason=$(echo "$SPLIT_JSON" | jget "['split']['rival_first_invalid']['reason']")
[[ "$reason" == "consensus-bip110" ]] || fail "rival_first_invalid reason '$reason' — expected 'consensus-bip110'"
info "getchainsplitinfo: rival=$RIVAL_H ours=$OURS_H reason=$reason — RDTS enforcement activated at exactly $ACTIVATION"

step "PASS: mandatory-signaling divergence at $WINDOW_LO, window closed at $((WINDOW_HI + 1)), RDTS activation at $ACTIVATION — all at their derived heights"
teardown_split "$KEEP"
exit 0
