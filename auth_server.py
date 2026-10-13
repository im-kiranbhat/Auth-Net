#!/usr/bin/env python3
"""Concurrent TCP authentication service integrated with a Ryu REST API."""
import csv
import hashlib
import hmac
import json
import os
import secrets
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

AUTH_HOST = os.getenv("AUTH_HOST", "0.0.0.0")
AUTH_PORT = int(os.getenv("AUTH_PORT", "5000"))
CONTROLLER_API = os.getenv("CONTROLLER_API", "http://127.0.0.1:8080").rstrip("/")
PROTECTED_IP = os.getenv("PROTECTED_IP", "10.0.0.4")
PROTECTED_PORT = int(os.getenv("PROTECTED_PORT", "9000"))
SESSION_TTL = int(os.getenv("SESSION_TTL", "300"))
EVENT_LOG = Path(os.getenv("EVENT_LOG", "events.csv"))
PBKDF2_ROUNDS = 200_000

def password_record(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ROUNDS)
    return {"salt": salt, "hash": digest.hex()}

def verify_password(password, record):
    candidate = password_record(password, record["salt"])["hash"]
    return hmac.compare_digest(candidate, record["hash"])

def build_users():
    # Lab-only demo credentials. Override/change before any use beyond a local demo.
    raw = os.getenv("DEMO_USERS", "")
    if raw:
        users = {}
        for item in raw.split(","):
            if ":" not in item:
                continue
            username, password = item.split(":", 1)
            users[username.strip()] = password_record(password.strip())
        return users
    return {"alice": password_record("alice123"), "bob": password_record("bob123")}

USERS = build_users()
sessions = {}
sessions_lock = threading.Lock()
log_lock = threading.Lock()

def log_event(event, username="", ip="", detail=""):
    new_file = not EVENT_LOG.exists()
    with log_lock:
        with EVENT_LOG.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            if new_file:
                writer.writerow(["timestamp", "event", "username", "client_ip", "detail"])
            writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), event, username, ip, detail])

def controller_request(path, payload=None, method=None):
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(
        CONTROLLER_API + path,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method or ("POST" if data is not None else "GET"),
    )
    with urllib.request.urlopen(request, timeout=3) as response:
        body = response.read().decode("utf-8")
        return json.loads(body) if body else {"ok": True}

def send_json(sock, obj):
    sock.sendall((json.dumps(obj, separators=(",", ":")) + "\n").encode())

def recv_json(reader):
    line = reader.readline()
    if not line:
        return None
    if len(line) > 65536:
        raise ValueError("message too large")
    return json.loads(line)

def expire_session(token, session):
    if time.time() - session["created"] > SESSION_TTL:
        try:
            controller_request("/revoke", {"ip": session["ip"]})
        except Exception as exc:
            log_event("REVOKE_ERROR", session["username"], session["ip"], str(exc))
        with sessions_lock:
            sessions.pop(token, None)
        log_event("SESSION_EXPIRED", session["username"], session["ip"])
        return True
    return False

def handle_client(conn, address):
    client_ip = address[0]
    username = ""
    token = None
    try:
        conn.settimeout(30)
        reader = conn.makefile("r", encoding="utf-8", newline="\n")
        send_json(conn, {"ok": True, "message": "Authentication service ready", "protocol": "jsonl"})
        while True:
            try:
                request = recv_json(reader)
            except (json.JSONDecodeError, ValueError) as exc:
                send_json(conn, {"ok": False, "error": "invalid_request", "message": str(exc)})
                continue
            if request is None:
                break
            action = str(request.get("action", "")).lower()

            if action == "login":
                username = str(request.get("username", ""))[:128]
                password = str(request.get("password", ""))[:1024]
                record = USERS.get(username)
                if not record or not verify_password(password, record):
                    log_event("LOGIN_FAILED", username, client_ip, "invalid credentials")
                    send_json(conn, {"ok": False, "message": "Invalid username or password"})
                    continue
                token = secrets.token_urlsafe(24)
                with sessions_lock:
                    sessions[token] = {"username": username, "ip": client_ip, "created": time.time()}
                log_event("LOGIN_SUCCESS", username, client_ip)
                send_json(conn, {"ok": True, "message": "Login successful", "token": token,
                                 "session_ttl": SESSION_TTL, "protected_service": f"{PROTECTED_IP}:{PROTECTED_PORT}"})

            elif action == "access":
                supplied_token = str(request.get("token", ""))
                with sessions_lock:
                    session = sessions.get(supplied_token)
                if not session or expire_session(supplied_token, session):
                    send_json(conn, {"ok": False, "message": "Session missing or expired; log in again"})
                    continue
                try:
                    result = controller_request("/grant", {"ip": session["ip"]})
                    log_event("ACCESS_GRANTED", session["username"], session["ip"], json.dumps(result))
                    send_json(conn, {"ok": True, "message": "Network access granted",
                                     "service": f"{PROTECTED_IP}:{PROTECTED_PORT}", "controller": result})
                except (urllib.error.URLError, TimeoutError, ValueError) as exc:
                    log_event("CONTROLLER_ERROR", session["username"], session["ip"], str(exc))
                    send_json(conn, {"ok": False, "message": "Controller unavailable; access not granted"})
            elif action == "logout":
                supplied_token = str(request.get("token", ""))
                with sessions_lock:
                    session = sessions.pop(supplied_token, None)
                if not session:
                    send_json(conn, {"ok": False, "message": "Unknown session"})
                    continue
                try:
                    result = controller_request("/revoke", {"ip": session["ip"]})
                    log_event("ACCESS_REVOKED", session["username"], session["ip"], json.dumps(result))
                    send_json(conn, {"ok": True, "message": "Logged out; network access revoked"})
                except Exception as exc:
                    log_event("REVOKE_ERROR", session["username"], session["ip"], str(exc))
                    send_json(conn, {"ok": False, "message": "Session closed, but controller revocation failed"})
            elif action == "status":
                supplied_token = str(request.get("token", ""))
                with sessions_lock:
                    session = sessions.get(supplied_token)
                valid = bool(session and not expire_session(supplied_token, session))
                send_json(conn, {"ok": valid, "message": "Session active" if valid else "Session inactive"})
            elif action == "quit":
                send_json(conn, {"ok": True, "message": "Goodbye"})
                break
            else:
                send_json(conn, {"ok": False, "message": "Unknown action"})
    except (ConnectionError, OSError, socket.timeout):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass

def main():
    log_event("SERVER_START", detail=f"{AUTH_HOST}:{AUTH_PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((AUTH_HOST, AUTH_PORT))
        server.listen(64)
        print(f"Authentication server listening on {AUTH_HOST}:{AUTH_PORT}")
        print(f"Controller API: {CONTROLLER_API}; protected service: {PROTECTED_IP}:{PROTECTED_PORT}")
        while True:
            conn, address = server.accept()
            threading.Thread(target=handle_client, args=(conn, address), daemon=True).start()

if __name__ == "__main__":
    main()
