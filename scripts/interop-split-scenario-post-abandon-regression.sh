#!/usr/bin/env bash
#
# BIP-110 split scenario: enforcement stays OFF permanently after capitulation.
#
# Every other capitulation-related scenario stops as soon as convergence is
# confirmed. Nothing verifies that abandonment is actually *permanent*: if a
# future regression made the node re-evaluate BIP-110 after a subsequent
# restart, or only suppress enforcement for the specific rival branch that
# triggered the original capitulation rather than the rule itself, an
# operator could find RDTS silently re-armed weeks later. This scenario
# capitulates normally, then has Core forge a SECOND, unrelated
# RDTS-violating block and confirms it's accepted with no fuss at all — no
# rejection, no new invalid marker, no split resurfacing — and repeats that
# check again after a further restart to prove it's not a one-restart fluke.
#
# Usage: ./scripts/interop-split-scenario-post-abandon-regression.sh [--keep]

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

# Forge an RDTS-violating block with a distinct payload byte and assert it
# is ACCEPTED (the opposite of the lib's forge_invalid_block, which asserts
# rejection — not reusable here since BIP-110 is expected to be off).
forge_and_expect_acceptance() {  # payload_byte label
    local payload_byte="$1" label="$2"
    local data raw funded signed pre_h new_hash new_height
    data=$(python3 -c "import sys; print(sys.argv[1] * 100)" "$payload_byte")
    raw=$(core createrawtransaction "[[],{\"data\":\"$data\"}]" | result_of)
    [[ -n "$raw" ]] || fail "$label: createrawtransaction failed"
    funded=$(core fundrawtransaction "[\"$raw\"]" | jget "['hex']")
    [[ -n "$funded" ]] || fail "$label: fundrawtransaction failed"
    signed=$(core signrawtransactionwithwallet "[\"$funded\"]" | jget "['hex']")
    [[ -n "$signed" ]] || fail "$label: signrawtransactionwithwallet failed"
    pre_h=$(core getblockcount | result_of)
    new_hash=$(core generateblock "[\"$CORE_ADDR\",[\"$signed\"]]" | jget "['hash']")
    [[ -n "$new_hash" ]] || fail "$label: generateblock failed"
    new_height=$((pre_h + 1))
    info "$label: forged a fresh RDTS-violating block $new_height ($new_hash) — must be accepted"

    wait_height "$PR_RPC" "$new_height" 60 || fail "$label: split-bitcoinpr did not accept the post-abandonment violating block — BIP-110 may have silently re-armed"
    local pr_tip
    pr_tip=$(pr getbestblockhash | result_of)
    [[ "$pr_tip" == "$new_hash" ]] || fail "$label: split-bitcoinpr accepted a DIFFERENT tip than the forged block ($pr_tip != $new_hash)"

    local split_field mode
    split_field=$(pr getchainsplitinfo | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['split'])")
    [[ "$split_field" == "None" ]] || fail "$label: a split resurfaced after abandonment ($split_field) — no new invalid marker should ever be created while abandoned"
    mode=$(pr getchainsplitinfo | jget "['bip110']['mode']")
    [[ "$mode" == "abandoned" ]] || fail "$label: bip110 mode is '$mode' — expected to stay 'abandoned'"
    info "$label: accepted normally, no split, mode still 'abandoned'"
}

setup_split

rival_h=$FORGED_HEIGHT
ours_h=$BASELINE
core_mine 5
rival_h=$((rival_h + 5))
wait_split_match "$rival_h" "$ours_h" 90 || fail "setup: monitor did not settle at rival=$rival_h ours=$ours_h"
[[ "$ARMED" == "True" ]] || fail "setup: armed='$ARMED' — expected True before capitulating"
info "armed at deficit $DEFICIT — capitulating normally"

capitulate_and_converge

step "Forge a second violating block right after capitulation"
forge_and_expect_acceptance "cc" "immediately post-abandonment"

step "Mine a few ordinary blocks to confirm the chain is healthy, not just tolerant of one fluke block"
core_mine 3
wait_height "$PR_RPC" "$((rival_h + 3))" 60 || fail "ordinary post-abandonment mining did not propagate"
info "ordinary mining after the violating block works fine too"

step "Restart split-bitcoinpr a SECOND time — confirm abandonment isn't a one-restart fluke"
docker restart split-bitcoinpr >/dev/null
wait_rpc "$PR_RPC" 120 || fail "split-bitcoinpr did not come back after the second restart"
MODE=$(pr getchainsplitinfo | jget "['bip110']['mode']")
[[ "$MODE" == "abandoned" ]] || fail "after second restart: mode='$MODE' — expected 'abandoned' to persist"
info "abandoned flag survived a second, unrelated restart"

step "Forge a third violating block after the second restart"
forge_and_expect_acceptance "dd" "after second restart"

step "PASS"
teardown_split "$KEEP"
exit 0
