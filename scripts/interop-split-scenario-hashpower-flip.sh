#!/usr/bin/env bash
#
# BIP-110 split scenario: the majority hashpower migrates to the BIP-110
# chain and forces the legacy chain to reorg onto it.
#
# Every other split scenario (interop-split-test.sh, and the dominant/flip/
# stalemate scripts) deliberately keeps split-bitcoinpr's own height BELOW
# the rival's, because split-core is a stock Bitcoin Core node with zero
# BIP-110 awareness: the forged block is only invalid under bitcoinpr's own
# rule, so Core just runs plain longest-valid-chain, and once a competing
# chain out-works Core's own, Core adopts it (see the "Switching to chain
# with more work" / "Connected block" log lines this produces — that's
# Core's ordinary fork choice, not a bitcoinpr taint-gate bypass).
#
# This scenario deliberately drives THAT behavior on purpose, modeling: the
# legacy (non-BIP110) chain has a commanding 144-block lead, then hashpower
# that was mining the legacy chain switches to mining the BIP-110 chain
# instead. split-bitcoinpr's own valid chain (never touched by the taint
# gate — it was never on the tainted branch to begin with) catches up block
# by block, and once it strictly out-works Core's chain, Core reorgs onto
# it — the softfork resolves in BIP-110's favor without any capitulation or
# operator action at all.
#
# Deficit trajectory (rival.height - ours.height), starting at 1:
#   Stage 1: core+143             -> deficit 144 (legacy's commanding lead)
#   Stage 2 (hashpower migrates, ours catches up in steps):
#     pr+40 -> 104 (armed)   pr+40 -> 64 (armed)   pr+40 -> 24 (armed)
#     pr+18 ->   6 (armed)   pr+1  ->  5 (disarmed) pr+4 -> 1 (disarmed)
#     pr+1  ->   0 (tied)    pr+1  -> -1 (ours strictly ahead — reorg trigger)
#   Then: wait for Core to actually reorg onto our chain, and confirm it
#   keeps following as we extend the lead a bit further.
#
# Usage: ./scripts/interop-split-scenario-hashpower-flip.sh [--keep]

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

# ─── Stage 1: legacy chain builds a commanding 144-block lead ─────────────

step "Stage 1: legacy (Core) chain mines out to a 144-block lead"
core_mine 100
core_mine 43
rival_h=$((rival_h + 143))

wait_split_match "$rival_h" "$ours_h" 120 || fail "stage 1: monitor did not settle at rival=$rival_h ours=$ours_h"
[[ "$FORK_H" == "$BASELINE" ]] || fail "stage 1: fork_height $FORK_H != $BASELINE"
(( DEFICIT == 144 )) || fail "stage 1: deficit $DEFICIT != 144"
[[ "$ARMED" == "True" ]] || fail "stage 1: armed='$ARMED' — expected True at deficit 144"
core_h_check=$(core getblockcount | result_of)
[[ "$core_h_check" == "$rival_h" ]] || fail "stage 1: core getblockcount $core_h_check != $rival_h"
SPLIT_ACTIVE=$(curl -sf --max-time 10 "$WEB/api/stats" | python3 -c "import sys,json; print(json.load(sys.stdin).get('split_active'))")
[[ "$SPLIT_ACTIVE" == "True" ]] || fail "stage 1: /api/stats split_active '$SPLIT_ACTIVE' — expected True"
info "stage 1: legacy chain leads by $DEFICIT blocks, armed=$ARMED, split_active=$SPLIT_ACTIVE"

# ─── Stage 2: hashpower migrates — our valid chain catches up in steps ────

step "Stage 2: hashpower migrates to the BIP-110 chain — mining to catch up"

STEPS=(40 40 40 18 1 4 1 1)
EXPECT_DEFICIT=(104 64 24 6 5 1 0 -1)
EXPECT_ARMED=(True True True True False False False False)

for i in "${!STEPS[@]}"; do
    inc=${STEPS[$i]}
    pr_mine "$inc"
    ours_h=$((ours_h + inc))
    exp_def=${EXPECT_DEFICIT[$i]}
    exp_armed=${EXPECT_ARMED[$i]}

    wait_split_match "$rival_h" "$ours_h" 90 || fail "stage 2 step $((i + 1)): monitor did not settle at rival=$rival_h ours=$ours_h"
    [[ "$FORK_H" == "$BASELINE" ]] || fail "stage 2 step $((i + 1)): fork_height $FORK_H != $BASELINE"
    (( DEFICIT == exp_def )) || fail "stage 2 step $((i + 1)): deficit $DEFICIT != $exp_def"
    [[ "$ARMED" == "$exp_armed" ]] || fail "stage 2 step $((i + 1)): armed='$ARMED' expected '$exp_armed' at deficit $DEFICIT"

    if (( exp_def > 0 )); then
        # Core must not have moved yet — it only has reason to reorg once we
        # STRICTLY out-work it, not while it's still nominally ahead.
        core_h_check=$(core getblockcount | result_of)
        [[ "$core_h_check" == "$rival_h" ]] || fail "stage 2 step $((i + 1)): core moved early (height $core_h_check) while still nominally ahead at deficit $exp_def"
    fi
    info "stage 2 step $((i + 1))/${#STEPS[@]}: ours=$ours_h rival=$rival_h deficit=$DEFICIT armed=$ARMED"
done

# ─── Stage 3: Core reorgs onto the now-longer, valid BIP-110 chain ────────

step "Stage 3: waiting for Core to reorg onto the BIP-110 chain"

wait_height "$CORE_RPC" "$ours_h" 90 || fail "Core did not reorg onto the BIP-110 chain (stuck below height $ours_h)"
core_tip=$(core getbestblockhash | result_of)
pr_tip=$(pr getbestblockhash | result_of)
[[ "$core_tip" == "$pr_tip" ]] || fail "Core reached height $ours_h but tip differs from ours (core=$core_tip pr=$pr_tip) — did not actually adopt our chain"
info "Core reorged onto the BIP-110 chain: height=$ours_h tip=$core_tip"

SPLIT_JSON=$(pr getchainsplitinfo)
DEFICIT=$(echo "$SPLIT_JSON" | jget "['split']['block_deficit']")
ARMED=$(echo "$SPLIT_JSON" | jget "['split']['capitulation_armed']")
(( DEFICIT < 0 )) || fail "post-reorg: expected a negative deficit (we're ahead), got $DEFICIT"
[[ "$ARMED" == "False" ]] || fail "post-reorg: armed='$ARMED' — expected False now that we lead"
SPLIT_ACTIVE=$(curl -sf --max-time 10 "$WEB/api/stats" | python3 -c "import sys,json; print(json.load(sys.stdin).get('split_active'))")
[[ "$SPLIT_ACTIVE" == "False" ]] || fail "post-reorg: /api/stats split_active '$SPLIT_ACTIVE' — expected False (out-worked rival is no longer a live threat)"
info "post-reorg: deficit=$DEFICIT armed=$ARMED split_active=$SPLIT_ACTIVE — the softfork resolved in BIP-110's favor with no capitulation needed"

# ─── Stage 4: confirm Core keeps following as our lead extends further ────

step "Stage 4: extend the lead further — Core must keep following"

pr_mine 5
ours_h=$((ours_h + 5))
wait_height "$PR_RPC" "$ours_h" 60 || fail "our own mining failed post-reorg"
wait_height "$CORE_RPC" "$ours_h" 90 || fail "Core fell behind again after initially reorging (height stuck below $ours_h)"
core_tip=$(core getbestblockhash | result_of)
pr_tip=$(pr getbestblockhash | result_of)
[[ "$core_tip" == "$pr_tip" ]] || fail "tips diverge after extending the lead (core=$core_tip pr=$pr_tip)"
info "Core stayed converged on the BIP-110 chain through further mining (height=$ours_h)"

step "PASS"
teardown_split "$KEEP"
exit 0
