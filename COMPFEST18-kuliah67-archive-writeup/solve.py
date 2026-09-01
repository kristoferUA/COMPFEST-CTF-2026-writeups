#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from chall import encrypt_block, open_sealed

N = 12

HIGH = [
    814, 3054, 3073, 2478,
    1374, 3970, 3836, 1142,
    664, 3332, 2904, 3245,
]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def plaintext_from_set(item: dict, mask: int) -> bytes:
    pt = bytearray.fromhex(item["base"])
    basis = [bytes.fromhex(x) for x in item["basis"]]
    for bit, vec in enumerate(basis):
        if (mask >> bit) & 1:
            pt[:] = xor_bytes(pt, vec)
    return bytes(pt)


def main() -> None:
    parser = argparse.ArgumentParser(description="Recover low bytes and open sealed.json")
    parser.add_argument("--verify-all", action="store_true", help="verify every known plaintext/ciphertext block, slower")
    args = parser.parse_args()

    records = json.loads(Path("records.json").read_text())
    ciphertexts = Path("records.bin").read_bytes()

    first_set = records["sets"][0]
    first_pt = plaintext_from_set(first_set, 0)
    first_offset = first_set["offset"] * N
    first_ct = ciphertexts[first_offset:first_offset + N]

    key_zero_low = [h << 8 for h in HIGH]
    trial_ct = encrypt_block(first_pt, key_zero_low)
    low = [a ^ b for a, b in zip(first_ct, trial_ct)]
    key = [(h << 8) | l for h, l in zip(HIGH, low)]

    checked = 1
    bad = 0 if encrypt_block(first_pt, key) == first_ct else 1

    if args.verify_all:
        checked = 0
        bad = 0
        for item in records["sets"]:
            for mask in range(item["count"]):
                pt = plaintext_from_set(item, mask)
                off = (item["offset"] + mask) * N
                ct = ciphertexts[off:off + N]
                if encrypt_block(pt, key) != ct:
                    bad += 1
                checked += 1

    sealed = json.loads(Path("sealed.json").read_text())
    secret = open_sealed(sealed, key).hex()
    suffix = hashlib.sha256(secret.encode()).hexdigest()[:16]
    flag = f"COMPFEST18{{{secret}_{suffix}}}"

    print(f"high: {HIGH}")
    print(f"low: {low}")
    print("key:")
    for value in key:
        print(f"  0x{value:05x}")
    print(f"checked blocks: {checked}")
    print(f"bad blocks: {bad}")
    print(f"sealed value: {secret}")
    print(f"flag: {flag}")


if __name__ == "__main__":
    main()
