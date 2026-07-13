#!/usr/bin/env python3
"""Minimal Stratum V1 miner that mines exactly ONE block against bitcoinpr1.

Used to deterministically verify the mining gateway (regtest block target is
trivial, so a valid nonce is found almost immediately). Mirrors the server's
header reconstruction in handle_v1_submit / assemble_mined_block.
"""
import socket, json, hashlib, sys, time

HOST, PORT = "127.0.0.1", 3333
WORKER = "bcrt1qngpn06rdppfde2w8f7qnukqxrumn6tjlhtjwle.sim"


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def compact_to_target(bits):
    exp = bits >> 24
    mant = bits & 0x007fffff
    if exp <= 3:
        return mant >> (8 * (3 - exp))
    return mant << (8 * (exp - 3))


def stratum_prevhash_to_internal(h):
    # Canonical Stratum V1 prevhash (template_prev_hash_stratum): internal LE
    # header words in order, bytes swapped within each 4-byte word. Undo the
    # per-word swap (same op as ESP-Miner/cgminer swap_endian_words) to
    # recover the internal bytes.
    b = bytes.fromhex(h)
    return b"".join(b[i:i+4][::-1] for i in range(0, 32, 4))


def main():
    s = socket.create_connection((HOST, PORT), timeout=15)
    f = s.makefile("rwb")

    def send(method, params, _id):
        f.write((json.dumps({"id": _id, "method": method, "params": params}) + "\n").encode())
        f.flush()

    def readline():
        return json.loads(f.readline().decode())

    send("mining.subscribe", ["sv1-sim/1.0"], 1)
    sub = readline()
    extranonce1 = sub["result"][1]
    en2_size = sub["result"][2]
    print(f"subscribed: en1={extranonce1} en2_size={en2_size}")

    send("mining.authorize", [WORKER, "x"], 2)

    job = None
    deadline = time.time() + 20
    while time.time() < deadline:
        msg = readline()
        if msg.get("method") == "mining.notify":
            job = msg["params"]
            break
        if msg.get("id") == 2:
            continue
    if job is None:
        print("ERROR: no mining.notify received")
        sys.exit(1)

    job_id, prevhash_s, cb1, cb2, branches, version_h, bits_h, ntime_h, clean = job[:9]
    print(f"job {job_id}: {len(branches)} merkle branch(es), bits={bits_h} clean={clean}")

    version = int(version_h, 16)
    bits = int(bits_h, 16)
    ntime = int(ntime_h, 16)
    target = compact_to_target(bits)
    prevhash_internal = stratum_prevhash_to_internal(prevhash_s)

    en2 = b"\x00" * en2_size
    coinbase = bytes.fromhex(cb1) + bytes.fromhex(extranonce1) + en2 + bytes.fromhex(cb2)
    merkle = sha256d(coinbase)
    for br in branches:
        merkle = sha256d(merkle + bytes.fromhex(br))

    head = version.to_bytes(4, "little") + prevhash_internal + merkle + ntime.to_bytes(4, "little") + bits.to_bytes(4, "little")
    found = None
    for nonce in range(0, 1 << 24):
        h = sha256d(head + nonce.to_bytes(4, "little"))
        if int.from_bytes(h, "little") <= target:
            found = nonce
            break
    if found is None:
        print("ERROR: no nonce found (unexpected on regtest)")
        sys.exit(1)
    print(f"found nonce={found} hash={sha256d(head + found.to_bytes(4,'little'))[::-1].hex()}")

    send("mining.submit", [WORKER, job_id, en2.hex(), f"{ntime:08x}", f"{found:08x}"], 3)
    # read until we get the submit response (id=3)
    for _ in range(10):
        resp = readline()
        if resp.get("id") == 3:
            print(f"submit response: result={resp.get('result')} error={resp.get('error')}")
            break
    s.close()


if __name__ == "__main__":
    main()
