#!/usr/bin/env python3
"""Python 3.14-friendly REST controller that programs OpenFlow rules via ovs-ofctl."""
from flask import Flask, jsonify, request
import ipaddress, os, subprocess, threading

app = Flask(__name__)
PROTECTED_IP = os.getenv("PROTECTED_IP", "10.0.0.4")
PROTECTED_PORT = int(os.getenv("PROTECTED_PORT", "9000"))
AUTHORIZED = set()
LOCK = threading.RLock()

def valid_ip(value):
    try:
        return str(ipaddress.IPv4Address(value)) == value
    except (ipaddress.AddressValueError, TypeError):
        return False

def bridges():
    result = subprocess.run(["ovs-vsctl", "list-br"], check=True, capture_output=True, text=True)
    return [x.strip() for x in result.stdout.splitlines() if x.strip()]

def run_flow(bridge, operation, rule):
    subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", operation, bridge, rule],
                   check=True, capture_output=True, text=True, timeout=5)

def install_base(bridge):
    run_flow(bridge, "add-flow", "priority=0,actions=NORMAL")
    run_flow(bridge, "add-flow", f"priority=150,ip,tcp,nw_dst={PROTECTED_IP},tp_dst={PROTECTED_PORT},actions=drop")

def install_allow(bridge, ip):
    run_flow(bridge, "add-flow",
             f"priority=200,ip,tcp,nw_src={ip},nw_dst={PROTECTED_IP},tp_dst={PROTECTED_PORT},actions=NORMAL")

@app.get("/health")
def health():
    return jsonify(ok=True, service="python314-ovs-acl-controller")

@app.get("/rules")
def rules():
    with LOCK:
        return jsonify(ok=True, authorized_ips=sorted(AUTHORIZED), protected_ip=PROTECTED_IP,
                       protected_port=PROTECTED_PORT, bridges=bridges())

@app.post("/grant")
def grant():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "")
    if not valid_ip(ip):
        return jsonify(ok=False, error="invalid IPv4 address"), 400
    try:
        with LOCK:
            bs = bridges()
            if not bs:
                return jsonify(ok=False, error="No OVS bridges found; start Mininet first"), 503
            AUTHORIZED.add(ip)
            for b in bs:
                install_base(b)
                install_allow(b, ip)
        return jsonify(ok=True, action="grant", ip=ip, bridges=bs,
                       protected_service=f"{PROTECTED_IP}:{PROTECTED_PORT}")
    except (subprocess.SubprocessError, OSError) as exc:
        return jsonify(ok=False, error=str(exc)), 500

@app.post("/revoke")
def revoke():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "")
    if not valid_ip(ip):
        return jsonify(ok=False, error="invalid IPv4 address"), 400
    try:
        with LOCK:
            AUTHORIZED.discard(ip)
            bs = bridges()
            for b in bs:
                run_flow(b, "del-flows", f"ip,tcp,nw_src={ip},nw_dst={PROTECTED_IP},tp_dst={PROTECTED_PORT}")
                run_flow(b, "add-flow", f"priority=150,ip,tcp,nw_dst={PROTECTED_IP},tp_dst={PROTECTED_PORT},actions=drop")
        return jsonify(ok=True, action="revoke", ip=ip, bridges=bs)
    except (subprocess.SubprocessError, OSError) as exc:
        return jsonify(ok=False, error=str(exc)), 500

if __name__ == "__main__":
    # Localhost-only management API for this lab prototype.
    app.run(host="127.0.0.1", port=8080, threaded=True, use_reloader=False)
