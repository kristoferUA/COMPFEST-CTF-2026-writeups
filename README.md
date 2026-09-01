# COMPFEST18 Writeups

Author: [kristoferUA](https://github.com/kristoferUA)

This repository collects five COMPFEST18 challenge writeups, solvers, and the original challenge materials that were included with them. Each challenge directory keeps its own detailed README unchanged; this page is a short map of the repository and the core idea behind each solution.

> Use the code and techniques here only in CTFs, labs, and other systems where you have permission to test.

## Challenges

| Challenge | Category | Exploit in brief |
| --- | --- | --- |
| [BurhanGuild Loader Incident](./COMPFEST18-BurhanGuild-Loader-Incident-writeup/) | Forensics / incident response | Correlate process, memory-map, network, and deleted-file evidence across several decoy captures. The only complete chain identifies the live memory-only loader, matches it to a carved deleted ZIP page, and yields the incident proof token. |
| [IT'S ME, BURHAN!](./COMPFEST18-BurhanQuest-writeup/) | Reverse engineering | Reverse the Java game's state-dependent password derivation, compute the hidden quest sequence, collect the required sigils, reconstruct Burhan's admin password, and invert the archive transformation to recover the flag. |
| [Jacobian as a Service](./COMPFEST18-Jacobian-as-a-Service-writeup/) | Misc / pwn | Abuse arbitrary file write to replace SageMath's crash helper, trigger a Jacobian segfault with a constant polynomial that passes the filter, and use the ptrace-enabled setgid helper plus GDB to execute `cat` with access to the protected flag. |
| [Kuliah67 Archive](./COMPFEST18-kuliah67-archive-writeup/) | Cryptography | Apply a 9th-order integral distinguisher to recover each 12-bit high key component independently, derive the low bytes from one known plaintext/ciphertext pair, and use the reconstructed key to authenticate and decrypt the sealed value. |
| [piyakcrypt](./COMPFEST18-piyakcrypt-writeup/) | Cryptography | Invert the data-panel transform to clone MT19937 from 624 outputs, predict the known half of biased ECDSA nonces, and solve the resulting Hidden Number Problem with an LLL/CVP lattice to recover the private key. |

## Repository layout

```text
COMPFEST18-writeups/
├── COMPFEST18-BurhanGuild-Loader-Incident-writeup/
├── COMPFEST18-BurhanQuest-writeup/
├── COMPFEST18-Jacobian-as-a-Service-writeup/
├── COMPFEST18-kuliah67-archive-writeup/
├── COMPFEST18-piyakcrypt-writeup/
└── README.md
```

Open a challenge directory for the complete analysis, exploit flow, usage instructions, and any included solver or challenge files.
