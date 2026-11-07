"""Build a FreeRADIUS tree for tests/radius/run.sh with the real renderer and the real agent snapshot store.

Runs inside the RADIUS image (python3, stdlib only) with the agent at /opt/easyeap-agent and the work directory at
/work. Reads the throwaway PKI from /work/pki, writes the rendered configuration to /work/state/raddb/live and the
authorization snapshot to /work/state/authz.db, exactly where the agent would. The 1.0.1 agent and renderer (from
git) are at /work/v101 for the version-skew checks.

    python3 fixture.py build              # render + snapshot (this build's API: wired VLANs)
    python3 fixture.py render-v101        # the 1.0.1 renderer's configuration, to /work/state/raddb/v101
    python3 fixture.py apply old-api      # this agent, an API from before wired 802.1X (no wired_vlan in entries)
    python3 fixture.py apply new          # this agent, this API
    python3 fixture.py apply v101-agent   # the 1.0.1 agent (a rollback), this API
    python3 fixture.py upgrade            # a store written by the 1.0.1 agent, opened by this one
    python3 fixture.py events             # shipped-event records (the agent's transform) as JSON lines
    python3 fixture.py classify < log     # the FreeRADIUS lines the agent keeps for the system log, as "level: message"
"""
from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

WORK = Path("/work")
STATE = WORK / "state"
os.environ["EASYEAP_RADIUS_STATE"] = str(STATE)
sys.path.insert(0, "/opt/easyeap-agent")
import easyeap_agent as agent  # noqa: E402
from render import render  # noqa: E402

TENANT_ID = "7e57e57e-0000-4000-8000-000000000001"
SECRET = "lab-shared-secret-0123456789abcdef"  # noqa: S105 — throwaway test secret
NET = os.environ.get("RADIUS_TEST_NET", "172.31.250")


def pem(name: str) -> str:
    return (WORK / "pki" / name).read_text()


def serial(name: str) -> str:
    out = subprocess.run(["openssl", "x509", "-in", str(WORK / "pki" / name), "-noout", "-serial"], capture_output=True, text=True, check=True).stdout
    return out.strip().split("=", 1)[1].upper().lstrip("0") or "0"


def client(n: str, name: str, vendor: str, networks: list[str], monitor: bool = False) -> dict:
    host = n.split("/")[0].split(".")[-1]
    return {"id": f"c0000000-0000-4000-8000-0000000000{int(host):02d}", "name": name, "vendor": vendor, "address": f"{NET}.{n}",
            "secret": SECRET, "coa": False, "coa_port": 3799, "networks": networks, "monitor": monitor}


def desired() -> dict:
    return {"version": "radius-test", "tenants": [{
        "id": TENANT_ID, "slug": "radtest", "name": "RADIUS test", "auth_port": 1812, "acct_port": 1813, "dedicated_ports": False,
        "tls_min_version": "1.2", "tls_session_cache": False, "session_timeout": 3600,
        "server_cert_pem": pem("server.pem"), "server_key_pem": pem("server.key"), "ca_pem": pem("issuing.pem") + pem("root.pem"),
        "crl_pem": pem("issuing.crl"),
        "clients": [
            client("10", "HQ WLC", "cisco-9800", ["wireless"]),
            client("11", "HQ Access 1", "cisco-switch", ["wired"]),
            # A UniFi gateway range with a Catalyst switch registered inside it: FreeRADIUS takes the longest prefix.
            client("16/28", "HQ UniFi", "unifi", ["wireless", "wired"]),
            client("20", "Lab Access", "cisco-switch", ["wired"], monitor=True),
        ],
    }]}


def snapshot(version: int, wired: bool = True) -> dict:
    alice, bob, carol = serial("alice.pem"), serial("bob.pem"), serial("carol.pem")
    now = int(time.time())
    entries = [
        # Alice: VLAN 100 on Wi-Fi; her VLAN maps to 110 on switch ports.
        {"serial": alice, "outcome": "allow", "reason": None, "vlan": 100, "wired_vlan": 110, "rule_id": "rule-staff", "username": "alice", "attributes": []},
        # Bob: VLAN 100 on Wi-Fi; on switch ports he keeps the port's own VLAN (none assigned).
        {"serial": bob, "outcome": "allow", "reason": None, "vlan": 100, "wired_vlan": None, "rule_id": "rule-contractors", "username": "bob", "attributes": []},
        # Carol: denied everywhere.
        {"serial": carol, "outcome": "deny", "reason": "policy_deny", "vlan": None, "wired_vlan": None, "rule_id": "rule-blocked", "username": "carol", "attributes": []},
    ]
    if not wired:
        for e in entries:
            del e["wired_vlan"]
    return {"tenant_id": TENANT_ID, "version": version, "built_at": now, "valid_until": now + 3600, "entries": entries, "digest": f"test-{version}"}


def v101():
    """The 1.0.1 agent module (and its renderer), loaded from /work/v101 under other names."""
    sys.path.insert(0, str(WORK / "v101"))
    for name in ("render", "easyeap_agent"):
        spec = importlib.util.spec_from_file_location(f"v101_{name}", WORK / "v101" / f"{name}.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        globals()[f"v101_{name}"] = mod
    return globals()["v101_easyeap_agent"], globals()["v101_render"]


def counts(conn: sqlite3.Connection) -> dict:
    return {"authz": conn.execute("SELECT COUNT(*) FROM authz").fetchone()[0],
            "authz_wired": conn.execute("SELECT COUNT(*) FROM authz_wired").fetchone()[0],
            "version": conn.execute("SELECT version FROM meta").fetchone()[0]}


def build() -> None:
    for d in (STATE / "spool", STATE / "run", STATE / "radacct"):
        d.mkdir(parents=True, exist_ok=True)
    render(desired(), STATE / "raddb" / "live", str(STATE))
    conn = agent.db(STATE / "authz.db")
    agent.apply_snapshot(conn, snapshot(1))
    print(json.dumps({"secret": SECRET, **counts(conn)}))


def render_v101() -> None:
    _, old_render = v101()
    old_render.render(desired(), STATE / "raddb" / "v101", str(STATE))
    print("ok")


def apply(variant: str) -> None:
    if variant == "v101-agent":
        old_agent, _ = v101()
        conn = old_agent.db()  # the 1.0.1 db() takes no path: STATE/authz.db
        old_agent.apply_snapshot(conn, snapshot(4))
    else:
        conn = agent.db(STATE / "authz.db")
        agent.apply_snapshot(conn, snapshot({"old-api": 2, "new": 3}[variant], wired=variant != "old-api"))
    print(json.dumps(counts(conn)))


def upgrade() -> None:
    """A store the 1.0.1 agent created and filled, opened by this agent: `authz` is untouched, `authz_wired` added."""
    path = WORK / "v101-authz.db"
    path.unlink(missing_ok=True)
    old_agent, _ = v101()
    old_agent.DB = path
    conn = old_agent.db()
    old_agent.apply_snapshot(conn, snapshot(7))
    before = conn.execute("SELECT * FROM authz ORDER BY serial").fetchall()
    cols_before = [r[1] for r in conn.execute("PRAGMA table_info(authz)")]
    conn.close()
    conn = agent.db(path)
    after = conn.execute("SELECT * FROM authz ORDER BY serial").fetchall()
    cols_after = [r[1] for r in conn.execute("PRAGMA table_info(authz)")]
    print(json.dumps({"same_rows": before == after, "same_columns": cols_before == cols_after, **counts(conn)}))


def events() -> None:
    for f in sorted((STATE / "spool").glob("auth-*.jsonl")):
        for line in f.read_text().splitlines():
            print(json.dumps(agent.transform("events", json.loads(line))))


def classify() -> None:
    for line in sys.stdin:
        hit = agent.classify_freeradius(line)
        if hit:
            print(f"{hit[0]}: {hit[1]}")


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "apply":
        apply(sys.argv[2])
    else:
        {"build": build, "render-v101": render_v101, "upgrade": upgrade, "events": events, "classify": classify}[cmd]()
