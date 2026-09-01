# Kuliah67 Archive

COMPFEST18 · crypto · author: [kristoferUA](https://github.com/kristoferUA)

The challenge starts from an archive account and eventually gives a small cryptography handout with an intentionally weak custom block cipher. The interesting part is not finding the flag string directly. The archive contains many chosen/known plaintext records and one sealed object. We have to recover the key from the records and then open the sealed gate.

Flag:

```text
COMPFEST18{5e9e8bf77207eca9c6906e80a57aa0e426f18ab8825a7b0f656cfa5d888a81c9_aefbd0dc566889bb}
```

## Challenge files

The archive contains:

```text
chall.py
records.json
records.bin
sealed.json
```

`chall.py` defines the cipher and the sealing format. `records.json` describes plaintext sets, while `records.bin` stores the matching ciphertext blocks. `sealed.json` contains the encrypted final secret.

The cipher uses 12-byte blocks:

```python
N = 12
P = 96
```

The key consists of 12 independent 20-bit words:

```text
key = [k0, k1, ..., k11]
0 <= ki < 2^20
```

The important split is:

```python
high[i] = key[i] >> 8
low[i]  = key[i] & 0xff
```

The round keys only depend on `high`:

```python
def _round_material(key):
    return b''.join((x >> 8).to_bytes(2, 'little') for x in key)
```

The final byte layer uses both parts, but in a separable way:

```python
seed = key[i]
rows = matrix(seed >> 8)
out[i] = apply(rows, q(x)) ^ (seed & 255)
```

So the attack can be split into two stages:

```text
1. Recover the 12 high parts with an integral property.
2. Recover the 12 low bytes with one known plaintext/ciphertext pair.
```

## What the records give us

`records.json` contains many affine plaintext sets. The useful ones have dimension `d = 9` and `count = 512`:

```json
{
  "d": 9,
  "base": "...",
  "basis": ["...", "...", "..."],
  "offset": 0,
  "count": 512
}
```

A block in one set is generated as:

```python
pt = base
for bit in range(d):
    if mask >> bit & 1:
        pt ^= basis[bit]
```

Since `d = 9`, each set contains all `2^9` points of a 9-dimensional affine space.

That is the intended hint: use a higher-order integral attack.

## Why the integral works

Each normal round is:

```python
s = bytes(_g(a ^ b) for a, b in zip(s, k))
s = _permute(s)
```

The nonlinear function `_g` contains only quadratic terms, for example:

```python
b[1] & b[2]
```

So one round at most doubles the algebraic degree. After three rounds the degree is at most:

```text
2^3 = 8
```

For a Boolean function with algebraic degree smaller than `d`, the xor of the function over a full `d`-dimensional affine space is zero.

Here:

```text
degree <= 8
d = 9
```

Therefore, before the final byte layer, every state bit should xor to zero across each 512-block set.

## Removing the final byte layer

The final layer for byte `i` is:

```text
c = M_high(q(x)) xor low
```

For a guessed `high`, we know `M_high`, so we can invert the linear part and then invert `q`:

```python
candidate_state_byte = qinv(M_high^-1(c))
```

For the correct `high`, the xor over every `d = 9` set becomes zero. Wrong `high` values fail quickly.

The low byte does not have to be known during this stage. It is only a constant xor at the end of the byte layer, and the challenge construction keeps the integral distinguisher valid for the correct matrix index.

For every byte position we brute-force only 4096 values:

```text
12 positions * 4096 high candidates
```

The recovered high parts were:

```python
high = [
    814, 3054, 3073, 2478,
    1374, 3970, 3836, 1142,
    664, 3332, 2904, 3245,
]
```

## Recovering the low bytes

Once the high parts are known, set all low bytes to zero:

```python
key0 = [h << 8 for h in high]
```

Encrypt one known plaintext block with `key0`. The result differs from the real ciphertext only by the final xor bytes:

```text
ct_real = ct_with_zero_low xor low
```

So:

```python
low[i] = ct_real[i] ^ ct_with_zero_low[i]
```

The recovered low bytes were:

```python
low = [
    141, 80, 135, 64,
    221, 1, 10, 74,
    23, 102, 3, 237,
]
```

Full key:

```python
key = [
    0x32e8d, 0xbee50, 0xc0187, 0x9ae40,
    0x55edd, 0xf8201, 0xefc0a, 0x4764a,
    0x29817, 0xd0466, 0xb5803, 0xcaded,
]
```

## Opening the sealed gate

`sealed.json` is authenticated and encrypted with material derived from the key:

```python
root = sha256(D + b'/seal/' + material(key))
ek = sha256(D + b'/enc/' + root)
mk = sha256(D + b'/mac/' + root)
```

After passing the HMAC check, the decrypted sealed value is:

```text
5e9e8bf77207eca9c6906e80a57aa0e426f18ab8825a7b0f656cfa5d888a81c9
```

The challenge format requires:

```text
COMPFEST18{64 lowercase hex + _ + sha256(that hex string)[:16]}
```

The suffix is:

```text
sha256("5e9e8bf77207eca9c6906e80a57aa0e426f18ab8825a7b0f656cfa5d888a81c9")[:16]
= aefbd0dc566889bb
```

Final flag:

```text
COMPFEST18{5e9e8bf77207eca9c6906e80a57aa0e426f18ab8825a7b0f656cfa5d888a81c9_aefbd0dc566889bb}
```

## Running it

Python 3.10 or newer is recommended.

Put the original challenge files next to `solve.py`:

```text
chall.py
records.json
records.bin
sealed.json
solve.py
```

Then run:

```bash
python solve.py
```

Expected output:

```text
checked blocks: 1
bad blocks: 0
sealed value: 5e9e8bf77207eca9c6906e80a57aa0e426f18ab8825a7b0f656cfa5d888a81c9
flag: COMPFEST18{5e9e8bf77207eca9c6906e80a57aa0e426f18ab8825a7b0f656cfa5d888a81c9_aefbd0dc566889bb}
```

Full verification is available too:

```bash
python solve.py --verify-all
```

The full check verifies all `33536` known plaintext/ciphertext blocks.

## Repository layout

```text
solve.py                  offline verifier and final decryptor
tools/integral_notes.py   small helper showing the q inverse and matrix inverse idea
tests/test_flag.py        sanity check for the final flag suffix
requirements.txt          runtime dependencies
requirements-dev.txt      test dependency list
LICENSE                   MIT license
README.md                 this writeup
```

## Notes

The attack is a classic integral-property known-plaintext attack against a low-degree SPN-like construction. The fatal design mistake is that the 20-bit key words are split by use: the 12 high bits select the round material and final matrices, while the 8 low bits are delayed until a final xor. That makes the hard-looking 240-bit key behave like twelve small 12-bit searches plus twelve trivial bytes.
