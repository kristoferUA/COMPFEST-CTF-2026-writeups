#!/usr/bin/env python3
from __future__ import annotations

from chall import _apply, _q, matrix


def q_inverse_table() -> list[int]:
    inv = [0] * 256
    for x in range(256):
        inv[_q(x)] = x
    return inv


def matrix_inverse_map(index: int) -> list[int]:
    rows = matrix(index)
    inv = [0] * 256
    for x in range(256):
        inv[_apply(rows, x)] = x
    return inv


def main() -> None:
    qinv = q_inverse_table()
    minv = matrix_inverse_map(814)
    print("q inverse table built:", len(qinv) == 256)
    print("matrix inverse map for high=814 built:", len(minv) == 256)
    print("example partial final-layer undo: qinv[minv[c]]")


if __name__ == "__main__":
    main()
