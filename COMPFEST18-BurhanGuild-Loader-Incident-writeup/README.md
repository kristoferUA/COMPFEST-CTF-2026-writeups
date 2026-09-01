# BurhanGuild Loader Incident

COMPFEST18 · for · author: kristoferUA

The challenge gives an incident-response package from an isolated internal Linux gateway. It contains several volatile memory captures, deleted-storage pages, a small parser plugin, and a YARA rule for BurhanGuild loader artifacts. The goal is to decide which evidence belongs to the same intrusion event, build the incident proof token, submit it to the questionnaire service, and recover the final flag.

Connection info:

```text
nc 34.2.147.230 7010
```

Flag:

```text
COMPFEST18{8urh4n9u1ld_0r10n_148_m3m0ry_0n1y_104d3r_c453_c1053d_4f73r_5upp1y_ch41n_7r4c3_826df6b2a62673a1a6cbbb1c63244dd8ddc2933381f52723343274716fabde}
```

## Challenge summary

The archive contains five memory captures and eight deleted pages:

```text
artifacts/captures/capture_2C91.raw
artifacts/captures/capture_7F3A.raw
artifacts/captures/capture_91BE.raw
artifacts/captures/capture_A812.raw
artifacts/captures/capture_D044.raw
artifacts/deleted_pages/page_00.bin ... page_07.bin
artifacts/integrity_manifest.json
plugins/bgloader_hunt.py
yara/burhanguild_memory_rules.yar
```

The helper script can parse BGMR v3 records from every capture:

```bash
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw metadata
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw processes
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw environment
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw maps
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw network
python3 plugins/bgloader_hunt.py -f artifacts/captures/capture_A812.raw files
```

I used those views to compare all captures instead of trusting a single suspicious artifact.

## Finding the correct capture

The same event had to connect the exploit chain, the memory-only loader, the deleted archive, and the active network session. A quick sweep over all captures was enough:

```bash
for f in artifacts/captures/*.raw; do
    echo "### $f"
    for cmd in metadata processes environment heap maps network files supply; do
        echo "--- $cmd"
        python3 plugins/bgloader_hunt.py -f "$f" "$cmd" 2>/dev/null || true
    done
done
```

Several captures contained decoys:

- `7F3A` had the JNDI payload, but only led to a staging-looking `libmetrics.so` artifact.
- `2C91` contained `memfd:libpam_bg.so (deleted)`, but it did not have the full matching chain.
- `91BE` had a deleted archive reference, but its carved archive pointed to `staging-node`.
- `D044` had `GCONV_PATH` and an external connection, but the mapped implant was `libmetrics.so` and the remote host looked like a mirror decoy.

The only capture that tied everything together was `capture_A812.raw`.

## Evidence from capture_A812

The process list showed a suspicious process that was visible in the scan source:

```text
scan   4787 | 4742 | [kworker/u8:7] | 2026-05-05T11:08:22Z
```

The parent chain was also suspicious:

```text
4693 java -> 4742 pkexec -> 4787 [kworker/u8:7]
```

Environment records linked the chain to a loader-style execution path:

```text
4787 | BG_MUTEX   | bguild-ce104cb0
4742 | GCONV_PATH | /tmp/.bg/gconv
```

The mapped region was a deleted in-memory library:

```text
PID  | VMA            | PERMS | NAME                         | BUILD ID             | REGION SHA256
4787 | 0x7f100008f000 | rwxp  | memfd:libpam_bg.so (deleted) | 542715c2e46252e4d790 | 1858064aa10396aafa565583707a0084c21370868e26d93b63309133687be223
```

The network view confirmed that this process was the live loader process:

```text
PID  | LOCAL             | REMOTE                           | STATE
4787 | 10.10.18.26:42110 | morrow-gate.wreckit.invalid:8443 | ESTABLISHED
```

The files view gave the deleted archive reference that needed to be matched with a deleted page:

```text
PID  | FD | MODE    | EVIDENCE REF    | PATH
4787 | 3  | deleted | EV-B1DC93988DBC | /dev/shm/.bg-cache/e0bafe9e.zip
```

So the important fields from memory were:

```text
capture_id = A812
loader_pid = 4787
build_id   = 542715c2e46252e4d790
archive_ev = EV-B1DC93988DBC
```

## Matching the deleted archive

The deleted pages contained multiple small ZIP remnants. The useful one was the archive carved from `page_05.bin`. Its metadata matched the live capture and the deleted file evidence reference:

```json
{
  "capture_id": "A812",
  "case_id": "BG-IR-2026-0505",
  "collection": "gateway-transfer",
  "evidence_ref": "EV-B1DC93988DBC",
  "host": "orion-lab",
  "sequence": "ed75ca67fea0a59a"
}
```

The transfer log pointed to the same deleted path:

```text
evidence_ref=EV-B1DC93988DBC
path=/dev/shm/.bg-cache/e0bafe9e.zip
collection=gateway-transfer
status=deleted
```

This removed the remaining ambiguity: the correct event was `orion-lab`, capture `A812`, loader PID `4787`, deleted archive `EV-B1DC93988DBC`.

## Building the proof token

After carving the loader region and extracting the required config/archive digests, the incident proof token was:

```text
BGLPROOF{orion-lab__cap-A812__loader-4787__implant-BG-94C2A04EC6__build-542715c2e46252e4d790__config-360251a5def08d12cb71e72d5a1609b0d34c9dfc9520197ad8b0cc2cd7cfb76b__archive-4bd20e26a2e63e75af61b07af3cf5dc219ca11a018588a3ce0ee4564338cf64a__digest-836d4fce93ec7b3077ab7c97820d29515ea5609cf346e40b76973ca37e2418ed}
```

Submitting it to the questionnaire service returned the flag:

```bash
printf '%s\n' 'BGLPROOF{orion-lab__cap-A812__loader-4787__implant-BG-94C2A04EC6__build-542715c2e46252e4d790__config-360251a5def08d12cb71e72d5a1609b0d34c9dfc9520197ad8b0cc2cd7cfb76b__archive-4bd20e26a2e63e75af61b07af3cf5dc219ca11a018588a3ce0ee4564338cf64a__digest-836d4fce93ec7b3077ab7c97820d29515ea5609cf346e40b76973ca37e2418ed}' | nc 34.2.147.230 7010
```

## Final solver behavior

The solve flow was:

1. Use `bgloader_hunt.py` to inspect every memory capture.
2. Identify the only capture where exploit traces, hidden process, memfd loader, C2 session, and deleted file reference agree.
3. Carve the loader region from `capture_A812.raw`.
4. Match `EV-B1DC93988DBC` against the ZIP remnant from `page_05.bin`.
5. Submit the reconstructed proof token and get the final flag.

## Repository layout

```text
README.md   writeup
```

## Notes

The main trick was not carving the first interesting object. There were several believable decoys in the captures, so I only trusted the chain that linked memory, process tree, network, deleted-file reference, and deleted-storage metadata at the same time.
