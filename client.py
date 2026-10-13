#!/usr/bin/env python3
"""Interactive client for the TCP authentication service."""
import argparse
import json
import socket

def recv_line(reader):
    line = reader.readline()
    if not line:
        raise ConnectionError("server closed connection")
    return json.loads(line)

def send_request(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    token = None
    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        reader = sock.makefile("r", encoding="utf-8")
        print(recv_line(reader).get("message", "Connected"))
        while True:
            print("\n1. Login\n2. Request protected-network access\n3. Session status\n4. Logout\n5. Quit")
            choice = input("Select: ").strip()
            if choice == "1":
                username = input("Username: ").strip()
                import getpass
                password = getpass.getpass("Password: ")
                send_request(sock, {"action": "login", "username": username, "password": password})
                response = recv_line(reader)
                print(response)
                if response.get("ok"):
                    token = response["token"]
            elif choice == "2":
                if not token:
                    print("Log in first.")
                    continue
                send_request(sock, {"action": "access", "token": token})
                print(recv_line(reader))
            elif choice == "3":
                send_request(sock, {"action": "status", "token": token or ""})
                print(recv_line(reader))
            elif choice == "4":
                if token:
                    send_request(sock, {"action": "logout", "token": token})
                    print(recv_line(reader))
                    token = None
                else:
                    print("No active session.")
            elif choice == "5":
                if token:
                    send_request(sock, {"action": "logout", "token": token})
                    print(recv_line(reader))
                send_request(sock, {"action": "quit"})
                print(recv_line(reader))
                break
            else:
                print("Choose 1-5.")

if __name__ == "__main__":
    main()
