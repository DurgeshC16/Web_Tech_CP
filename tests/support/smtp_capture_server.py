#!/usr/bin/env python3
"""Minimal SMTP capture server for CertiVault delivery tests.

Accepts a connection, advertises AUTH LOGIN/PLAIN (accepting any
credentials), and writes each received message to <outdir>/<n>.eml. No
external dependencies; used only by tests/test_smtp_live.php.

Usage: python smtp_capture_server.py <port> <outdir>
Prints "READY" on stdout once listening.
"""
import base64
import os
import socket
import sys
import threading

HOST = "127.0.0.1"


def handle(conn, outdir, counter):
    f = conn.makefile("rb")

    def send(line):
        conn.sendall(line.encode() + b"\r\n")

    send("220 certivault-test ESMTP")
    data_mode = False
    message = []
    while True:
        raw = f.readline()
        if not raw:
            break

        if data_mode:
            if raw.strip() == b".":
                data_mode = False
                path = os.path.join(outdir, "%d.eml" % counter[0])
                with open(path, "wb") as fh:
                    fh.write(b"".join(message))
                counter[0] += 1
                message = []
                send("250 OK queued")
            else:
                # Undo SMTP dot-stuffing.
                if raw.startswith(b".."):
                    raw = raw[1:]
                message.append(raw)
            continue

        line = raw.decode("utf-8", "replace").strip()
        cmd = line.split(" ", 1)[0].upper()

        if cmd in ("EHLO", "HELO"):
            send("250-certivault-test")
            send("250-AUTH LOGIN PLAIN")
            send("250-8BITMIME")
            send("250 OK")
        elif cmd == "AUTH":
            parts = line.split(" ")
            mech = parts[1].upper() if len(parts) > 1 else "LOGIN"
            if mech == "PLAIN" and len(parts) > 2:
                send("235 2.7.0 Authentication successful")
            else:
                send("334 " + base64.b64encode(b"Username:").decode())
                f.readline()
                send("334 " + base64.b64encode(b"Password:").decode())
                f.readline()
                send("235 2.7.0 Authentication successful")
        elif cmd == "MAIL":
            send("250 OK")
        elif cmd == "RCPT":
            send("250 OK")
        elif cmd == "DATA":
            send("354 End data with <CR><LF>.<CR><LF>")
            data_mode = True
        elif cmd == "RSET":
            message = []
            send("250 OK")
        elif cmd == "NOOP":
            send("250 OK")
        elif cmd == "QUIT":
            send("221 Bye")
            break
        else:
            send("250 OK")

    try:
        conn.close()
    except OSError:
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 2525
    outdir = sys.argv[2] if len(sys.argv) > 2 else "."
    os.makedirs(outdir, exist_ok=True)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(5)

    print("READY", flush=True)
    counter = [0]
    try:
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=handle, args=(conn, outdir, counter), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()


if __name__ == "__main__":
    main()
