#!/usr/bin/env python3
"""Simple concurrent TCP service used to verify network access rules."""
import argparse
import socket
import threading
import time

def handle(conn, address):
    try:
        conn.settimeout(20)
        conn.sendall(b"Protected service connected. Send a line of text.\n")
        reader = conn.makefile("rb")
        while True:
            line = reader.readline(4096)
            if not line:
                break
            message = line.decode("utf-8", errors="replace").rstrip("\r\n")
            if message.lower() == "quit":
                conn.sendall(b"Goodbye\n")
                break
            reply = f"ACK {time.strftime('%H:%M:%S')}: {message}\n"
            conn.sendall(reply.encode())
    except (OSError, socket.timeout):
        pass
    finally:
        conn.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="10.0.0.4")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.host, args.port))
        server.listen(32)
        print(f"Protected service listening on {args.host}:{args.port}")
        while True:
            conn, address = server.accept()
            threading.Thread(target=handle, args=(conn, address), daemon=True).start()

if __name__ == "__main__":
    main()
