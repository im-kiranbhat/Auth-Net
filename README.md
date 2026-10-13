# Authentication and Network Access Control (SDN Socket Programming)

A complete teaching/demo project containing a concurrent TCP authentication server, interactive TCP client, protected TCP service, Flask REST controller, Open vSwitch flow-rule management, and a Mininet topology. This edition avoids Ryu and is suitable for modern Python versions where Flask is available.

## Files

- `auth_server.py` — TCP JSON-lines authentication server, password hashing, session tokens/timeouts, CSV event logging, and controller API calls.
- `client.py` — interactive TCP client (login, request access, status, logout).
- `protected_service.py` — TCP service hosted at `10.0.0.4:9000` in Mininet.
- `controller/auth_controller.py` — local REST API that adds/removes Open vSwitch flow rules using `ovs-ofctl`.
- `topology.py` — Mininet hosts `h2`, `h3`, `h4` and switches `s1`, `s2`; initializes base rules.
- `tests/test_protocol.py` — basic protocol/password tests.

Demo credentials: `alice / alice123` and `bob / bob123`. These are lab-only credentials.

## 1. Install dependencies (one time)

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch curl python3-venv netcat-openbsd
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If your folder is elsewhere, `cd` to the extracted `auth_network_access_control` folder instead. If `.venv` already exists and Flask is installed, do not recreate it.

## 2. Run the demo in this order

Use four terminals. Do not close the running terminals during the demo.

### Terminal 1 — start Mininet (Person 3)

```bash
sudo mn -c
sudo -E python3 topology.py
```

At the `mininet>` prompt:

```text
nodes
net
pingall
h4 python3 $yourpath/protected_service.py --host 10.0.0.4 --port 9000 &
```



### Terminal 2 — start the SDN controller (Person 2)

```bash
sudo -E .venv/bin/python controller/auth_controller.py
```

Leave it running. From Terminal 3, check the API:

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/rules
```

The controller's REST API is deliberately bound to `127.0.0.1` for this local lab. It controls bridges named `s1` and `s2` created by Mininet.

### Terminal 3 — run the authentication server (Person 1)

```bash
source .venv/bin/activate
python3 auth_server.py
```

### Terminal 4 — run the interactive client (Person 1)

```bash
source .venv/bin/activate
python3 client.py --host 127.0.0.1 --port 5000
```

Menu: `1` login, `2` request protected-network access, `3` session status, `4` logout, `5` quit. Login with `alice` / `alice123`; try an incorrect password too.

**Integration note:** A client run on the Ubuntu host reaches the authentication server from `127.0.0.1`; it is not Mininet host `h2` (`10.0.0.2`). So the client menu proves the TCP authentication/session flow, but does not by itself authorize `h2`. For a reliable Mininet ACL demonstration, use the controller API below to grant/revoke the specific Mininet host IP. Do not claim those two demonstrations are end-to-end joined unless you have separately configured the client to originate from the Mininet host IP.

## 3. Demonstrate the SDN grant/revoke behavior

With Mininet running and the protected service listening, use a normal Ubuntu terminal (not the `mininet>` prompt).

### A. Test the controller and initial policy

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/rules
```

At `mininet>` test h2 before granting access:

```text
h2 nc -vz -w 3 10.0.0.4 9000
```

Expected: failure/timeout while the protected-service drop rule is active.

### B. Grant h2 access

```bash
curl -X POST http://127.0.0.1:8080/grant -H 'Content-Type: application/json' -d '{"ip":"10.0.0.2"}'
curl http://127.0.0.1:8080/rules
```

At `mininet>`:

```text
h2 nc -vz -w 3 10.0.0.4 9000
```

Expected: connection succeeds if the OVS rules and protected service are running correctly.

### C. Revoke h2 access

```bash
curl -X POST http://127.0.0.1:8080/revoke -H 'Content-Type: application/json' -d '{"ip":"10.0.0.2"}'
curl http://127.0.0.1:8080/rules
```

At `mininet>`:

```text
h2 nc -vz -w 3 10.0.0.4 9000
```

Expected: failure/timeout again. Record actual results; do not claim success if the test does not match expectations.

## 4. Cleanup

Exit Mininet by typing `exit` at `mininet>`, then run:

```bash
sudo mn -c
```

Stop the controller/auth server with `Ctrl+C` in their respective terminals.

## Troubleshooting

- `curl ...:8080/health` connection refused: start Terminal 2 controller and leave it running.
- `No such file or directory` for `protected_service.py`: use the full path printed by topology startup; ensure the ZIP was fully extracted and all files are in the same project folder.
- `RTNETLINK answers: File exists`: exit any old Mininet session and run `sudo mn -c` before restarting `topology.py`. Do not run multiple topologies simultaneously.
- No OVS bridges in `/rules`: start Mininet before testing `/grant`.
- Connection still succeeds after revoke or fails after grant: inspect the output of `/rules`, make sure the service is listening, and verify OVS flow rules with `sudo ovs-ofctl -O OpenFlow13 dump-flows s1` and `sudo ovs-ofctl -O OpenFlow13 dump-flows s2`.

## Academic/security note

This is a local teaching prototype. Authentication traffic is plain TCP, the REST API has no authentication, the demo credentials are not production credentials, and access decisions based on source IP are simplified. Use only in an isolated lab environment.
