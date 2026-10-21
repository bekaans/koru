#!/usr/bin/env python3
"""Pulsar event recorder: collects real event samples for the koru-pulsar translation tests.

Runs as root inside the VM (the engine API socket is open to root only):

    sudo python3 /koru/lab/scripts/pulsar-record-event.py --duration 60 --output /tmp/events.jsonl \
        --filter koru-sample --filter 18080

Connects to the running pulsard's engine API (/var/run/pulsar.sock, the `/monitor` WebSocket) and
receives every event on the bus in Pulsar's own serde JSON form (pulsar_core::event::Event). Events
whose raw JSON text contains one of the --filter values are written unchanged, one event per line,
to the --output file. Uses only the Python standard library.

Note: this tool is only for collecting test data in the lab VM; the Koru agent does not
depend on the engine API (ADR-0001, embedded module).
"""

import argparse
import base64
import os
import socket
import struct
import sys
import threading


def el_sikis(sock):
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        "GET /monitor HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(request.encode("ascii"))
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("the connection closed during the handshake")
        buffer += chunk
        if len(buffer) > 65536:
            raise RuntimeError("the handshake response is too long")
    header, rest = buffer.split(b"\r\n\r\n", 1)
    first_line = header.split(b"\r\n", 1)[0].decode("ascii", "replace")
    if " 101 " not in first_line:
        raise RuntimeError(f"WebSocket handshake failed: {first_line}")
    return rest


class Reader:
    def __init__(self, sock, buffer):
        self.sock = sock
        self.buffer = buffer

    def read(self, n):
        while len(self.buffer) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError
            self.buffer += chunk
        data, self.buffer = self.buffer[:n], self.buffer[n:]
        return data


def send_frame(sock, opcode, data):
    # Client-to-server frames are masked (RFC 6455 section 5.3).
    mask = os.urandom(4)
    length = len(data)
    if length < 126:
        header = struct.pack("!BB", 0x80 | opcode, 0x80 | length)
    elif length < 65536:
        header = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, length)
    else:
        header = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, length)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    sock.sendall(header + mask + masked)


def messages(sock, reader):
    fragments = []
    while True:
        b1, b2 = reader.read(2)
        fin = b1 & 0x80
        opcode = b1 & 0x0F
        length = b2 & 0x7F
        if length == 126:
            (length,) = struct.unpack("!H", reader.read(2))
        elif length == 127:
            (length,) = struct.unpack("!Q", reader.read(8))
        if length > 16 * 1024 * 1024:
            raise RuntimeError("frame too large")
        mask = reader.read(4) if b2 & 0x80 else None
        data = reader.read(length)
        if mask:
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        if opcode == 0x8:
            return
        if opcode == 0x9:
            send_frame(sock, 0xA, data)
            continue
        if opcode in (0x1, 0x0):
            fragments.append(data)
            if fin:
                yield b"".join(fragments).decode("utf-8")
                fragments = []


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--sock", default="/var/run/pulsar.sock")
    ap.add_argument("--duration", type=float, required=True, help="recording duration (s)")
    ap.add_argument("--output", required=True, help="JSONL output file")
    ap.add_argument("--filter", action="append", default=[],
                    help="text that must appear in the raw JSON (repeatable; any one is enough)")
    arg = ap.parse_args()
    if not arg.filter:
        ap.error("at least one --filter is required (to avoid recording every system event)")

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(arg.sock)
    rest = el_sikis(sock)
    reader = Reader(sock, rest)
    # Reading is blocking; when the duration ends the socket is closed and reading ends with EOFError/OSError.
    # (A read timeout is not used: it could lose data mid-frame.)
    timer = threading.Timer(arg.duration, lambda: sock.shutdown(socket.SHUT_RDWR))
    timer.daemon = True
    written = 0
    seen = 0
    with open(arg.output, "w", encoding="utf-8") as output:
        print(f"[record] ready; recording for {arg.duration:.0f} s", file=sys.stderr, flush=True)
        timer.start()
        try:
            for text in messages(sock, reader):
                seen += 1
                if any(f in text for f in arg.filter):
                    output.write(text + "\n")
                    output.flush()
                    written += 1
        except (EOFError, OSError):
            pass
        finally:
            timer.cancel()
            sock.close()
    print(f"[record] events seen {seen}, written {written}", file=sys.stderr)


if __name__ == "__main__":
    main()
