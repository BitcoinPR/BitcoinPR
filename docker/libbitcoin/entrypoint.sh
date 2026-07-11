#!/bin/bash
# Initialise the libbitcoin database on first boot, then start the server.
# bs --initchain CREATES [database]directory — it must not exist yet.
# The volume is mounted at /data/libbitcoin; the database lives in the
# "chain" subdirectory so Docker's bind-mount creation doesn't block --initchain.
#
# initchain preallocates large bucket tables (~880MB+) and can be interrupted
# partway — e.g. OOM-killed under a tight mem_limit. That leaves a half-created
# chain/ dir that the server cannot open ("Failure starting blockchain"). A
# naive "init only when chain/ is absent" guard then skips re-init forever and
# the container restart-loops. To self-heal, we gate init on an explicit
# completion marker written ONLY after a successful initchain: if chain/ exists
# without the marker, the previous init was interrupted, so we wipe and retry.
set -euo pipefail

DB_DIR="/data/libbitcoin/chain"
INIT_MARKER="/data/libbitcoin/.initchain-complete"

if [[ ! -f "$INIT_MARKER" ]]; then
    if [[ -d "$DB_DIR" ]]; then
        echo "[entrypoint] chain/ present but no completion marker — previous init was interrupted; wiping and retrying ..."
        rm -rf "$DB_DIR"
    fi
    echo "[entrypoint] Initialising libbitcoin database in ${DB_DIR} ..."
    bs --initchain --config /etc/libbitcoin/bs.cfg
    # Reached only if initchain exited 0 (set -e aborts on failure/OOM-kill,
    # leaving the marker unwritten so the next boot wipes and retries).
    touch "$INIT_MARKER"
    echo "[entrypoint] Database initialised."
fi

echo "[entrypoint] Starting libbitcoin server ..."
exec bs --config /etc/libbitcoin/bs.cfg
