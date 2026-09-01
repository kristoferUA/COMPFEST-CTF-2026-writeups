# IT'S ME, BURHAN!

COMPFEST18 · reverse engineering · author: [kristoferUA](https://github.com/kristoferUA)

The challenge gives us a Java terminal game called `BurhanQuest`. We receive a normal wanderer account:

```text
frieren / frieren
```

Burhan, the guildmaster, keeps the flag behind his admin account. The goal is to recover Burhan's password, open the sealed archive, and decode the encrypted flag.

```bash
nc 34.2.22.80 30077
```

Flag:

```text
COMPFEST18{bUR_BuR_BUr_buRh4n_h4Un7s_m3_t!L_t0D4y_Bz556NYuf7SooE1i}
```

## Challenge summary

At first the JAR looks like a simple menu program. Frieren can see the profile, list quests, complete quests, export data, and read an archive sigil. Burhan has an additional admin menu with option `13`:

```text
13. Lihat Arsip Tersegel
```

The local JAR does not contain the real flag. The archive content is taken from the remote environment, then transformed with a per-run operation chain. Because of that, hardcoding anything from the local run gives only a fake/dev value.

The interesting parts are:

```text
profile: level + initial coins
quest list: rewards
hidden quest chain: 3 quest IDs
sigil-pertempuran: integer per completed hidden quest
sigil-arsip: hex value
sigil-ekspor: hex value
admin password: derived from all collected values
sealed archive: transformed flag bytes
```

## Reversing the password generation

The admin password is not static. It is derived from the current game state.

The hidden quest chain is generated from Frieren's level and initial coins:

```python
seed = sha256(i2b(level) + i2b(initial_coins))
n = first_8_bytes_as_positive_long(seed) % 4896
chain = perm_unrank(n, 18, 3)
```

The three quest IDs are zero-based in the algorithm, but the remote menu expects names like `Q6`, `Q17`, `Q12`.

After each selected quest we collect a battle sigil:

```text
sigil-pertempuran [Q6]: 25146
sigil-pertempuran [Q6>Q17]: 34480
sigil-pertempuran [Q6>Q17>Q12]: 32532
```

Between those quests we also query archive/export sigils:

```text
sigil-arsip
sigil-ekspor
sigil-arsip
```

These values, together with level, initial coins, and the final coin total after rewards, are hashed into the admin password. The password uses a rotated base32 alphabet and a chain of reversible operations over 5-bit indices.

For the solved instance the recovered values were:

```text
level=13
initial_coins=7583
chain=[6, 17, 12]
sigil-pertempuran #1=25146
sigil-arsip #1=b85d0a8b2511
sigil-pertempuran #2=34480
sigil-ekspor=c74a418cd4d2
sigil-pertempuran #3=32532
sigil-arsip #2=9dd54338417d
admin_password=U7CLJFB4MBHPSVOQ
ops=[11, 9, 10, 8, 0, 12, 16, 14, 6]
```

## Decoding the sealed archive

Burhan's option `13` prints a long hex string, not the flag directly:

```text
ff9ec1aa51fb319b033871d8bf94d79830e1535f06cc1c2bf5b986c9c4d071c94ad3bc01ccd5674e846e270e46aef6a80e5f8b20aab11a84e7fb1cc1ece0bb69d2f302
```

The same `ops` chain used during password derivation is reused for the archive bytes. To recover the plaintext, we apply inverse byte operations in reverse order:

```python
cur = bytes.fromhex(sealed_hex)
for op in reversed(ops):
    cur = inv_byte_op(op, cur)
print(cur.decode())
```

This gives the flag:

```text
COMPFEST18{bUR_BuR_BUr_buRh4n_h4Un7s_m3_t!L_t0D4y_Bz556NYuf7SooE1i}
```

## Exploit flow

The solver automates the whole path:

1. Connect to the remote instance and submit the CTFd access token.
2. Login as `frieren/frieren`.
3. Parse `Level Pengembara` and `Koin Didapatkan`.
4. Parse quest rewards.
5. Compute the hidden 3-quest chain.
6. Complete the three hidden quests and collect all required sigils.
7. Rebuild Burhan's password.
8. Login as `burhan`.
9. Open admin option `13`.
10. Decode the sealed archive into the final flag.

## Running it

Python 3.10 or newer is recommended.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
```

Run against the remote service:

```bash
python solve.py \
  --host 34.2.22.80 \
  --port 30077 \
  --token 'ctfd_your_token_here'
```

The token can also be passed through an environment variable:

```bash
export CTFD_TOKEN='ctfd_your_token_here'
python solve.py --host 34.2.22.80 --port 30077
```

Offline archive decoding is supported too:

```bash
python solve.py --decode \
  'ff9ec1aa51fb319b033871d8bf94d79830e1535f06cc1c2bf5b986c9c4d071c94ad3bc01ccd5674e846e270e46aef6a80e5f8b20aab11a84e7fb1cc1ece0bb69d2f302' \
  '[11, 9, 10, 8, 0, 12, 16, 14, 6]'
```

## Repository layout

```text
solve.py                  live exploit and offline decoder
tools/decode_archive.py   tiny wrapper for decoding sealed archive hex
tests/test_decode.py      regression test for the known archive
requirements.txt          runtime dependencies
LICENSE                   MIT license
README.md                 this writeup
```

## Notes

The main trap was assuming that Burhan's password was static or derived from the CTFd token. It is not. The token is only used by the infrastructure to start the personal instance. The actual admin password is derived from the in-game state and sigils.

Another small bug-prone part is reading the sealed archive. After `Flag guild:` the program prints a newline first, so a naive `recvline()` can return an empty line. The solver skips empty lines until it finds a valid hex blob.
