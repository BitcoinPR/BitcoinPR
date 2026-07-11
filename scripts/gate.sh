#!/usr/bin/env bash
# scripts/gate.sh — Static quality gate for the workspace.
#
# Runs the checks every change must pass BEFORE the interop suite:
#   1. cargo fmt --check                                  (L1)
#   2. cargo clippy --workspace --all-targets -D warnings (L2)
#   3. cargo audit          — advisory scan               (M7)
#   4. cargo machete        — unused dependencies         (M7)
#   5. cargo test --workspace
#
# House convention: run this, then rebuild the bitcoinpr images and run
# scripts/interop-test.sh against the live cluster (see docs/interop-cluster.md).
#
# The repo's cargo toolchain lives in the claude-rust-build container; run
# this script inside it:
#   docker exec claude-rust-build /build/scripts/gate.sh
#
# Exit code: 0 if every gate passed, 1 otherwise.

set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

FAILED=0

run_gate() {
    local name="$1"; shift
    echo "── gate: ${name} ──"
    if "$@"; then
        echo "── ${name}: OK"
    else
        echo "── ${name}: FAILED"
        FAILED=1
    fi
    echo
}

# --all-features matters: the docker images build with --features full,
# and feature-gated code (e.g. the indexing catch-up path in node.rs) is
# invisible to a featureless workspace build.
run_gate "fmt"     cargo fmt --check
run_gate "clippy"  cargo clippy --workspace --all-targets --all-features --quiet -- -D warnings
run_gate "audit"   cargo audit
run_gate "machete" cargo machete
run_gate "test"    cargo test --workspace --all-features --quiet

if [[ "$FAILED" == 0 ]]; then
    echo "ALL GATES PASSED"
else
    echo "GATE FAILURES — see above"
fi
exit "$FAILED"
