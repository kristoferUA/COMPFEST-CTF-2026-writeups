#!/usr/bin/env python3
from pwn import remote, context
import argparse
import hashlib
import re
import sys
import os

HOST = "34.2.22.80"
PORT = 30077
TOKEN = None
ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
MASK63 = (1 << 63) - 1


def i2b(x: int) -> bytes:
    return int(x).to_bytes(4, "big", signed=False)


def sha(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()


def p_long(digest: bytes) -> int:
    # Java helper p.b(byte[]): first 8 digest bytes as long, with sign bit cleared.
    return int.from_bytes(digest[:8], "big") & MASK63


def perm_unrank(v: int, n: int, k: int) -> list[int]:
    # k-permutation unranking over [0..n-1].
    items = list(range(n))
    out = []
    for pos in range(k):
        block = 1
        for t in range(k - pos - 1):
            block *= n - pos - 1 - t
        idx = v // block
        v %= block
        out.append(items.pop(idx))
    return out


def quest_chain(g: int, h: int) -> list[int]:
    n = p_long(sha(i2b(h) + i2b(g))) % 4896
    return perm_unrank(n, 18, 3)  # zero-based quest IDs


def base32_indices(data: bytes, count: int) -> list[int]:
    bits = "".join(f"{b:08b}" for b in data)
    return [int(bits[i * 5:(i + 1) * 5], 2) for i in range(count)]


def alphabet(rot: int) -> str:
    return ALPHA[rot:] + ALPHA[:rot]


def br5(v: int) -> int:
    return int(f"{v:05b}"[::-1], 2)


def br8(v: int) -> int:
    return int(f"{v:08b}"[::-1], 2)


def ror(v: int, n: int) -> int:
    return ((v >> n) | (v << (8 - n))) & 0xff


def rol(v: int, n: int) -> int:
    return ror(v, 8 - n)


def gray(v: int) -> int:
    return (v ^ (v >> 1)) & 0xff


def inv_gray(v: int) -> int:
    x = v
    s = 1
    while s < 8:
        x ^= x >> s
        s <<= 1
    return x & 0xff


def byte_op(op: int, data: bytes) -> bytes:
    y = list(data)
    n = len(y)
    x = [0] * n

    if op == 0:
        return bytes(y)
    if op == 1:
        return bytes(y[::-1])
    if op == 2:
        return bytes(v ^ 0xff for v in y)
    if op == 3:
        return bytes(br8(v) for v in y)
    if op == 4:
        return bytes(rol(v, 3) for v in y)
    if op == 5:
        return bytes(gray(v) for v in y)
    if op == 6:
        return bytes(rol(v, 2) for v in y)
    if op == 7:
        return bytes((v + i) & 0xff for i, v in enumerate(y))
    if op == 8:
        return bytes((v * 7) & 0xff for v in y)
    if op == 9:
        x[0] = y[0]
        for i in range(1, n):
            x[i] = y[i] ^ x[i - 1]
        return bytes(x)
    if op == 10:
        return bytes(y[(i + 2) % n] for i in range(n))
    if op == 11:
        return bytes((v * 3) & 0xff for v in y)
    if op == 12:
        return bytes(((v * 3) + i) & 0xff for i, v in enumerate(y))
    if op == 13:
        return bytes(rol(y[n - 1 - i], 1) for i in range(n))
    if op == 14:
        return bytes(y[0::2] + y[1::2])
    if op == 15:
        return bytes(y[(i + 1) % n] for i in range(n))
    if op == 16:
        x[0] = y[0]
        for i in range(1, n):
            x[i] = (y[i] + y[i - 1]) & 0xff
        return bytes(x)
    if op == 17:
        x[0] = y[0]
        for i in range(1, n):
            x[i] = (y[i] + x[i - 1]) & 0xff
        return bytes(x)
    raise ValueError(f"bad byte op {op}")


def inv_byte_op(op: int, data: bytes) -> bytes:
    y = list(data)
    n = len(y)
    x = [0] * n

    if op == 0:
        return bytes(y)
    if op == 1:
        return bytes(y[::-1])
    if op == 2:
        return bytes(v ^ 0xff for v in y)
    if op == 3:
        return bytes(br8(v) for v in y)
    if op == 4:
        return bytes(ror(v, 3) for v in y)
    if op == 5:
        return bytes(inv_gray(v) for v in y)
    if op == 6:
        return bytes(ror(v, 2) for v in y)
    if op == 7:
        return bytes((v - i) & 0xff for i, v in enumerate(y))
    if op == 8:
        return bytes((v * 183) & 0xff for v in y)
    if op == 9:
        x[0] = y[0]
        for i in range(1, n):
            x[i] = y[i] ^ y[i - 1]
        return bytes(x)
    if op == 10:
        for i, v in enumerate(y):
            x[(i + 2) % n] = v
        return bytes(x)
    if op == 11:
        return bytes((v * 171) & 0xff for v in y)
    if op == 12:
        return bytes(((v - i) * 171) & 0xff for i, v in enumerate(y))
    if op == 13:
        for i, v in enumerate(y):
            x[n - 1 - i] = ror(v, 1)
        return bytes(x)
    if op == 14:
        k = (n + 1) // 2
        for i in range(k):
            x[2 * i] = y[i]
        for i in range(n - k):
            x[2 * i + 1] = y[k + i]
        return bytes(x)
    if op == 15:
        for i, v in enumerate(y):
            x[(i + 1) % n] = v
        return bytes(x)
    if op == 16:
        x[0] = y[0]
        for i in range(1, n):
            x[i] = (y[i] - x[i - 1]) & 0xff
        return bytes(x)
    if op == 17:
        x[0] = y[0]
        for i in range(1, n):
            x[i] = (y[i] - y[i - 1]) & 0xff
        return bytes(x)
    raise ValueError(f"bad inverse byte op {op}")


def inv_int_op(op: int, y: list[int]) -> list[int]:
    n = len(y)
    x = [0] * n

    if op == 0:
        return y[:]
    if op == 1:
        return y[::-1]
    if op == 2:
        return [31 - v for v in y]
    if op == 3:
        return [br5(v) for v in y]
    if op == 4:
        tab = [0, 1, 3, 2, 6, 7, 5, 4, 12, 13, 15, 14, 10, 11, 9, 8,
               24, 25, 27, 26, 30, 31, 29, 28, 20, 21, 23, 22, 18, 19, 17, 16]
        inv = [0] * 32
        for i, v in enumerate(tab):
            inv[v] = i
        return [inv[v] for v in y]
    if op == 5:
        return [31 if v == 31 else (16 * v) % 31 for v in y]
    if op == 6:
        return [31 if v == 31 else (8 * v) % 31 for v in y]
    if op == 7:
        return [(v - i) & 31 for i, v in enumerate(y)]
    if op == 8:
        return [(23 * v) & 31 for v in y]
    if op == 9:
        return [(11 * v) & 31 for v in y]
    if op == 10:
        x[0] = y[0]
        for i in range(1, n):
            x[i] = y[i] ^ y[i - 1]
        return x
    if op == 11:
        for i, v in enumerate(y):
            x[(i + 2) % n] = v
        return x
    if op == 12:
        x[0] = y[0]
        for i in range(1, n):
            x[i] = (y[i] - y[i - 1]) & 31
        return x
    if op == 13:
        x[0] = y[0]
        for i in range(1, n):
            x[i] = (y[i] - x[i - 1]) & 31
        return x
    if op == 14:
        return [(11 * ((v - i) & 31)) & 31 for i, v in enumerate(y)]
    if op == 15:
        for i, v in enumerate(y):
            x[n - 1 - i] = 31 if v == 31 else (16 * v) % 31
        return x
    if op == 16:
        for i, v in enumerate(y):
            if i < n // 2:
                x[2 * i] = v
            else:
                x[2 * (i - n // 2) + 1] = v
        return x
    if op == 17:
        for i, v in enumerate(y):
            x[(i + 1) % n] = v
        return x
    raise ValueError(f"bad inverse int op {op}")


def make_admin_password(g: int, h: int, bp: int, cp: str, bq: int, dq: str, br: int, cr: str, s: int) -> tuple[str, list[int]]:
    chunks = [
        i2b(h), i2b(g), i2b(bp), bytes.fromhex(cp), i2b(bq), bytes.fromhex(dq), i2b(br), bytes.fromhex(cr), i2b(s)
    ]
    allv = p_long(sha(b"".join(chunks))) % 17643225600
    ops = perm_unrank(allv, 18, 9)
    order_seed = p_long(sha(i2b(g) + i2b(h))) % 362880
    order = perm_unrank(order_seed, 9, 9)
    rot = allv % 32

    ordered = [chunks[i] for i in order]
    st = sha(byte_op(ops[0], ordered[0]))
    for op, chunk in zip(ops[1:], ordered[1:]):
        st = sha(st + byte_op(op, chunk))

    cur = base32_indices(st, 16)
    for op in reversed(ops):
        cur = inv_int_op(op, cur)

    password = "".join(alphabet(rot)[v] for v in cur)
    return password, ops


def decode_archive(hex_blob: str, ops: list[int]) -> str:
    cur = bytes.fromhex(hex_blob.strip())
    for op in reversed(ops):
        cur = inv_byte_op(op, cur)
    return cur.decode("utf-8", errors="replace")


def rx(pattern: str, text: str, name: str, flags: int = 0):
    m = re.search(pattern, text, flags)
    if not m:
        print(f"[-] Could not parse {name}")
        print(text[-2000:])
        sys.exit(1)
    return m


def as_text(data: bytes) -> str:
    return data.decode("utf-8", errors="ignore")


def recv_choice(io, timeout: int = 20) -> str:
    data = io.recvuntil(b"Masukkan pilihan:", timeout=timeout)
    if not data:
        print("[-] Timeout waiting for menu")
        sys.exit(1)
    return as_text(data)


def send_choice(io, choice: int | str, timeout: int = 20) -> str:
    data = recv_choice(io, timeout=timeout)
    io.sendline(str(choice).encode())
    return data


def login(io, user: str, password: str) -> str:
    send_choice(io, 1)
    io.recvuntil(b"Masukkan username:", timeout=10)
    io.sendline(user.encode())
    io.recvuntil(b"Masukkan password:", timeout=10)
    io.sendline(password.encode())
    out = recv_choice(io, timeout=20)
    if "Login berhasil" not in out:
        print(f"[-] Login failed for {user}:{password}")
        print(out[-2000:])
        sys.exit(1)
    return out


def get_profile(io) -> tuple[int, int]:
    io.sendline(b"1")
    out = recv_choice(io)
    h = int(rx(r"Level Pengembara:\s*(\d+)", out, "level").group(1))
    g = int(rx(r"Koin Didapatkan:\s*(\d+)", out, "coins").group(1))
    print(f"[+] Frieren: level={h}, initial_coins={g}")
    return g, h


def get_rewards(io) -> dict[int, int]:
    io.sendline(b"2")
    out = recv_choice(io)
    rewards = {}
    for m in re.finditer(r"ID Quest:\s*Q(\d+).*?Reward Koin:\s*(\d+)", out, re.S):
        rewards[int(m.group(1))] = int(m.group(2))
    if len(rewards) < 18:
        print(f"[-] Parsed only {len(rewards)} quest rewards")
        print(out[-2000:])
        sys.exit(1)
    return rewards


def take_quest(io, qid: int) -> int:
    io.sendline(b"5")
    io.recvuntil(b"Masukkan ID Quest", timeout=10)
    # Consume the rest of the prompt if it has not arrived yet. Sending immediately is fine.
    io.sendline(f"Q{qid}".encode())
    out = recv_choice(io, timeout=30)
    sig = int(rx(r"sigil-pertempuran \[[^\]]+\]:\s*(\d+)", out, f"battle sigil Q{qid}").group(1))
    print(f"[+] Q{qid}: sigil-pertempuran={sig}")
    return sig


def get_archive_sigil(io) -> str:
    io.sendline(b"7")
    out = recv_choice(io)
    sig = rx(r"sigil-arsip:\s*([0-9a-fA-F]+)", out, "sigil-arsip").group(1).lower()
    print(f"[+] sigil-arsip={sig}")
    return sig


def get_export_sigil(io) -> str:
    io.sendline(b"6")
    out = recv_choice(io, timeout=20)
    sig = rx(r"sigil-ekspor:\s*([0-9a-fA-F]+)", out, "sigil-ekspor").group(1).lower()
    print(f"[+] sigil-ekspor={sig}")
    return sig


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--token", default=os.getenv("CTFD_TOKEN") or TOKEN, help="CTFd access token. Can also be supplied through CTFD_TOKEN")
    parser.add_argument("--decode", nargs=2, metavar=("HEX", "OPS"), help="offline decode: HEX and Python-style ops list, e.g. '[11,9,10,8,0,12,16,14,6]'")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    context.log_level = "debug" if args.debug else "info"

    if args.decode:
        hex_blob, ops_raw = args.decode
        ops = [int(x) for x in re.findall(r"\d+", ops_raw)]
        print(decode_archive(hex_blob, ops))
        return

    if not args.token:
        print("[-] Provide --token or set CTFD_TOKEN")
        sys.exit(1)

    io = remote(args.host, args.port)

    io.recvuntil(b"CTFd access token:", timeout=15)
    io.sendline(args.token.encode())

    login(io, "frieren", "frieren")
    g, h = get_profile(io)
    rewards = get_rewards(io)

    chain0 = quest_chain(g, h)
    chain = [x + 1 for x in chain0]
    print(f"[+] chain={chain}")

    bp = take_quest(io, chain[0])
    cp = get_archive_sigil(io)
    bq = take_quest(io, chain[1])
    dq = get_export_sigil(io)
    br = take_quest(io, chain[2])
    cr = get_archive_sigil(io)

    s = g + rewards[chain[0]] + rewards[chain[1]] + rewards[chain[2]]
    admin_password, ops = make_admin_password(g, h, bp, cp, bq, dq, br, cr, s)
    print(f"[+] admin_password={admin_password}")
    print(f"[+] ops={ops}")

    # logout Frieren, then let login() consume the top-level menu prompt.
    # Do NOT call recv_choice() here: it would consume the prompt and login()
    # would wait forever for a second one.
    io.sendline(b"0")
    login(io, "burhan", admin_password)

    io.sendline(b"13")
    io.recvuntil(b"Flag guild:", timeout=10)

    # After the label the program prints a newline, then the sealed hex on the next line.
    # recvline() right after recvuntil("Flag guild:") can therefore return only b"\n".
    hex_blob = ""
    for _ in range(8):
        line = io.recvline(timeout=5)
        if not line:
            continue
        cand = line.strip().decode(errors="ignore")
        if re.fullmatch(r"[0-9a-fA-F]+", cand):
            hex_blob = cand.lower()
            break

    if not hex_blob:
        print("[-] Could not read sealed hex after admin option 13")
        sys.exit(1)

    print(f"[+] sealed_hex={hex_blob}")

    flag = decode_archive(hex_blob, ops)
    print(f"\nFLAG: {flag}")

    try:
        io.close()
    except Exception:
        pass


if __name__ == "__main__":
    main()
