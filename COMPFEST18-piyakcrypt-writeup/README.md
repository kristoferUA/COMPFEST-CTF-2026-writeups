# piyakcrypt

COMPFEST18 · crypto · author: [kristoferUA](https://github.com/kristoferUA)

The challenge gives a menu service with several secp256k1 ECDSA units. Each unit has its own private key, but all private keys share the same known high and low 20-bit tags. The service also exposes a "data panel" backed by Python's `random`, and signatures use the same PRNG to build the high half of every nonce.

```text
nc 34.2.147.230 3002
```

Flag:

```text
COMPFEST18{b1as3d_n0nc3_mt_r3c0v3ry_lll_hnp_go_brr_727e3a9724b244c1}
```

## Challenge summary

The important part of `chall.py` is the private key generation:

```python
tag_high = random.getrandbits(20)
tag_low = random.getrandbits(20)
_ = [random.getrandbits(32) for _ in range(622)]

piece = int.from_bytes(os.urandom(D_BYTES), "big")
secret = (tag_high << 236) | (piece << 20) | tag_low
```

Every unit has a different random middle `piece`, but the top and bottom 20 bits are shared and can be printed from the damaged record.

The signature code is normal ECDSA:

```python
s = inverse(k) * (z + r * secret) mod n
```

but the nonce is biased:

```python
chunk_a = make_piece(random.getrandbits(64), random.getrandbits(64), total_signatures)
chunk_b = int.from_bytes(os.urandom(16), "big")
k = (chunk_a << 128) | chunk_b
```

So the high 128 bits of `k` come from Python `random`, while the low 128 bits stay unknown.

## What the data panel leaks

The data panel prints 32-bit PRNG outputs after applying an invertible transform:

```python
entry = panel_value(random.getrandbits(32), pos)
```

`panel_value` only uses xor, rotate, and addition modulo `2^32`, so it can be reversed.

The first two PRNG outputs are partially leaked as `tag_high` and `tag_low`, then the challenge skips 622 more 32-bit outputs. That means exactly 624 MT19937 outputs are consumed before the data panel starts.

By reading the data panel 8 times, we get:

```text
8 * 78 = 624
```

full 32-bit outputs. After reversing `panel_value` and untempering those values, we can reconstruct the Python MT19937 state and predict future `random.getrandbits(64)` calls.

## Turning signatures into HNP

For one unit, request 4 signatures. Since we know the MT state, we know the high part of each nonce:

```text
k_i = K_i * 2^128 + u_i
```

where `K_i` is known and `u_i < 2^128` is unknown.

The private key has the form:

```text
d = known_high_low + p * 2^20
```

where `p < 2^216` is the unknown middle piece.

From ECDSA:

```text
s_i * k_i = z_i + r_i * d mod n
```

Substituting both forms gives:

```text
r_i * 2^20 * p - s_i * u_i =
s_i * K_i * 2^128 - z_i - r_i * known_high_low mod n
```

This is a small Hidden Number Problem instance. There are 4 equations, one shared unknown `p`, and four bounded nonce tails `u_i`. A short CVP/LLL lattice recovers `p`, then the full private key `d`.

## Final solver behavior

The solver:

1. Connects to the service and reads `record_high` and `record_low`.
2. Reads the data panel 8 times.
3. Reverses `panel_value` and reconstructs MT19937.
4. Requests 4 signatures from unit `0`.
5. Predicts the high 128 bits of each nonce.
6. Solves the HNP with LLL/CVP.
7. Submits the recovered private key as the integer code.

The successful run ended with:

```text
COMPFEST18{b1as3d_n0nc3_mt_r3c0v3ry_lll_hnp_go_brr_727e3a9724b244c1}
```

## Running it

Python 3.10 or newer is recommended.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
python solve.py
```

The host and port can be overridden:

```bash
python solve.py --host 34.2.147.230 --port 3002
```

For a local check against the provided challenge files:

```bash
python solve.py local
```

That local run prints the fake flag from the attachment, which is useful for testing the exploit before attacking the remote service.

## Repository layout

```text
solve.py          live exploit
chall.py          original challenge source
flag.txt          local fake flag from attachments
requirements.txt  runtime dependencies
files/            original downloaded attachments
```

## Notes

The order of `random.getrandbits(64)` matters. The nonce high part is not just two raw 64-bit values concatenated: both values are passed through `fold_piece`, and `make_piece` also depends on the global signature index.

The lattice solve also needs integer arithmetic only. Accidentally converting 200-bit coordinates through Python `float` breaks recovery, so the solver extracts CVP coordinates with exact integer division.
