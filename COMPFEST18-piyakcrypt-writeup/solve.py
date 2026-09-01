#!/usr/bin/env python3
import os
import re
import socket
import subprocess
import sys
import time
import random
import argparse

from fpylll import IntegerMatrix, LLL, CVP


N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A_HIGH_SIZE = 20
A_LOW_SIZE = 20
B_SIZE = 128
D_SIZE = 256 - A_HIGH_SIZE - A_LOW_SIZE
UNIT_COUNT = 5
TABLE_SIZE = 78
TABLE_LIMIT = 9
MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1
B = 1 << 128
LOW = 1 << A_LOW_SIZE
P_BOUND = 1 << D_SIZE


def rol32(x, r):
    r &= 31
    return ((x << r) | (x >> (32 - r))) & MASK32


def ror32(x, r):
    r &= 31
    return ((x >> r) | (x << (32 - r))) & MASK32


def rol64(x, r):
    r &= 63
    return ((x << r) | (x >> (64 - r))) & MASK64


def unpanel_value(y, pos):
    salt = (0xA5A5A5A5 + pos * 0x6D2B79F5) & MASK32
    bump = (0x9E3779B9 ^ (pos * 0x85EBCA6B)) & MASK32
    x = ror32((y - bump) & MASK32, pos * 7 + 3)
    return x ^ salt


def unshift_right_xor(y, shift):
    x = y
    for _ in range(5):
        x = y ^ (x >> shift)
    return x & MASK32


def unshift_left_xor_mask(y, shift, mask):
    x = y
    for _ in range(5):
        x = y ^ ((x << shift) & mask)
    return x & MASK32


def untemper(y):
    y = unshift_right_xor(y, 18)
    y = unshift_left_xor_mask(y, 15, 0xEFC60000)
    y = unshift_left_xor_mask(y, 7, 0x9D2C5680)
    y = unshift_right_xor(y, 11)
    return y & MASK32


def fold_piece(x, pos, lane):
    x ^= ((pos + 1) * 0xD6E8FEB86659FD93 + lane * 0xA0761D6478BD642F) & MASK64
    x = rol64(x, 17 + pos * 9 + lane * 23)
    x = (x * 0x9E6C63D0676A9A99 + 0xD1B54A32D192ED03) & MASK64
    return x


def make_piece(a, b, pos):
    return (fold_piece(a, pos, 0) << 64) | fold_piece(b, pos, 1)


def clone_random(outputs):
    state = tuple(untemper(x) for x in outputs)
    rng = random.Random()
    rng.setstate((3, state + (624,), None))
    return rng


class Tube:
    def recv_until(self, marker, timeout=10):
        raise NotImplementedError

    def sendline(self, s):
        raise NotImplementedError

    def close(self):
        pass


class SocketTube(Tube):
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(0.25)
        self.buf = b""

    def recv_until(self, marker, timeout=10):
        marker = marker.encode()
        end = time.time() + timeout
        while marker not in self.buf and time.time() < end:
            try:
                chunk = self.sock.recv(65536)
                if not chunk:
                    break
                self.buf += chunk
            except socket.timeout:
                pass
        idx = self.buf.find(marker)
        if idx >= 0:
            idx += len(marker)
            out, self.buf = self.buf[:idx], self.buf[idx:]
            return out.decode(errors="replace")
        out, self.buf = self.buf, b""
        return out.decode(errors="replace")

    def sendline(self, s):
        self.sock.sendall((str(s) + "\n").encode())

    def close(self):
        self.sock.close()


class ProcTube(Tube):
    def __init__(self, argv, cwd):
        self.p = subprocess.Popen(
            argv,
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        os.set_blocking(self.p.stdout.fileno(), False)
        self.buf = b""

    def recv_until(self, marker, timeout=10):
        marker = marker.encode()
        end = time.time() + timeout
        while marker not in self.buf and time.time() < end:
            try:
                chunk = self.p.stdout.read(65536)
                if chunk:
                    self.buf += chunk
                else:
                    time.sleep(0.02)
            except BlockingIOError:
                time.sleep(0.02)
        idx = self.buf.find(marker)
        if idx >= 0:
            idx += len(marker)
            out, self.buf = self.buf[:idx], self.buf[idx:]
            return out.decode(errors="replace")
        out, self.buf = self.buf, b""
        return out.decode(errors="replace")

    def sendline(self, s):
        self.p.stdin.write((str(s) + "\n").encode())
        self.p.stdin.flush()

    def close(self):
        self.p.kill()


def solve_unit(tag_high, tag_low, signatures, rng):
    high_part = tag_high << (D_SIZE + A_LOW_SIZE)
    known = high_part | tag_low
    coeffs = []
    cs = []
    for pos, sig in enumerate(signatures):
        chunk_a = make_piece(rng.getrandbits(64), rng.getrandbits(64), pos)
        z, r, s = sig
        a = (r * LOW) % N
        b = (-s) % N
        c = (s * ((chunk_a << B_SIZE) % N) - z - r * known) % N
        coeffs.append((a, b))
        cs.append(c)

    m = len(signatures)
    var_count = 1 + m
    dim = m + var_count
    scales = [N // P_BOUND, N // B, N // B, N // B, N // B]
    basis = IntegerMatrix(dim, dim)

    for i in range(m):
        basis[i, i] = N
    for j in range(var_count):
        row = m + j
        for i in range(m):
            if j == 0:
                basis[row, i] = coeffs[i][0]
            elif j == i + 1:
                basis[row, i] = coeffs[i][1]
        basis[row, m + j] = scales[j]

    target = list(cs)
    bounds = [P_BOUND] + [B] * m
    weight = N
    for i in range(m):
        for j in range(dim):
            basis[i, j] *= weight
    for row in range(m, dim):
        for i in range(m):
            basis[row, i] *= weight
    target = [x * weight for x in target]
    for j in range(var_count):
        target.append((bounds[j] // 2) * scales[j])

    LLL.reduction(basis)
    close = CVP.closest_vector(basis, tuple(target))
    vals = []
    for j in range(var_count):
        coord = int(close[m + j])
        if coord % scales[j] != 0:
            return None
        vals.append(coord // scales[j])

    p = vals[0]
    lows = vals[1:]
    if not (0 <= p < P_BOUND) or any(not (0 <= u < B) for u in lows):
        return None

    for i, (z, r, s) in enumerate(signatures):
        if (coeffs[i][0] * p + coeffs[i][1] * lows[i] - cs[i]) % N != 0:
            return None
    return known | (p << A_LOW_SIZE)


def interact(tube):
    tube.recv_until("menu>")

    tube.sendline(2)
    damaged = tube.recv_until("menu>")
    tag_high = int(re.search(r"record_high = 0x([0-9a-f]+)", damaged).group(1), 16)
    tag_low = int(re.search(r"record_low\s+= 0x([0-9a-f]+)", damaged).group(1), 16)
    print(f"[+] tag_high={tag_high:#x} tag_low={tag_low:#x}")

    raw = []
    for _ in range(8):
        tube.sendline(5)
        panel = tube.recv_until("menu>")
        for pos_s, val_s in re.findall(r"entry_(\d+) = 0x([0-9a-f]{8})", panel):
            pos = int(pos_s)
            raw.append(unpanel_value(int(val_s, 16), pos))
    assert len(raw) == 624
    rng = clone_random(raw)
    print("[+] cloned MT state")

    signatures = []
    for i in range(4):
        tube.sendline(3)
        tube.recv_until("):")
        tube.sendline(0)
        tube.recv_until("Message (text or 0xHEX):")
        tube.sendline(f"msg-{i}")
        out = tube.recv_until("menu>")
        z = int(re.search(r"z = (\d+)", out).group(1))
        r = int(re.search(r"r = (\d+)", out).group(1))
        s = int(re.search(r"s = (\d+)", out).group(1))
        signatures.append((z, r, s))
        print(f"[+] signature {i} collected")

    secret = solve_unit(tag_high, tag_low, signatures, rng)
    if secret is None:
        raise RuntimeError("lattice solve failed")
    print(f"[+] secret={secret}")

    tube.sendline(6)
    tube.recv_until("Code (integer):")
    tube.sendline(secret)
    return tube.recv_until("}", timeout=10)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", nargs="?", choices=["remote", "local"], default="remote")
    parser.add_argument("--host", default="34.2.147.230")
    parser.add_argument("--port", type=int, default=3002)
    args = parser.parse_args()

    if args.mode == "local":
        tube = ProcTube(["python3", "chall.py"], os.path.dirname(os.path.abspath(__file__)))
    else:
        tube = SocketTube(args.host, args.port)
    try:
        print(interact(tube))
    finally:
        tube.close()


if __name__ == "__main__":
    main()
