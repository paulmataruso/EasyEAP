"""The lab switch's dataset (deploy/lab/switch): a Catalyst-like set of IF-MIB, ENTITY-MIB, CISCO-AUTH-FRAMEWORK-MIB and
CISCO-ERR-DISABLE-MIB rows, as net-snmp pass_persist triples [oid, type, value], on stdout.

    python3 lab_switch.py '{"serial": "FOC1234X0AB", "ports": {...}, "sessions": [...], "errdis": {...}}'

ports:    {"<n>": {"control": 1|2|3, "open": true|false}} for GigabitEthernet1/0/<n> (ifIndex 7 + n); others are auto, closed
sessions: [{"port": n, "mac": "02:00:...", "status": 6, "method": "dot1x"|"mab", "vlan": 0, "critical": 0, "user": ""}]
errdis:   {"<n>": cause} (2 = BPDU guard)
"""
import json
import sys

CAF = ".1.3.6.1.4.1.9.9.656"
METHODS = {"dot1x": 2, "mab": 3}


def build(spec: dict) -> list:
    rows = []
    add = lambda o, t, v: rows.append([o, t, str(v)])  # noqa: E731
    add(".1.3.6.1.2.1.47.1.1.1.1.5.1", "integer", 3)            # entPhysicalClass: chassis
    add(".1.3.6.1.2.1.47.1.1.1.1.5.2", "integer", 9)            # a module
    add(".1.3.6.1.2.1.47.1.1.1.1.11.1", "string", spec.get("serial", "FOC1234X0AB"))
    add(".1.3.6.1.2.1.47.1.1.1.1.13.1", "string", "C9300-48P")
    add(".1.3.6.1.4.1.9.9.548.1.1.1.0", "integer", 300)         # cErrDisableRecoveryInterval
    add(CAF + ".1.1.2.1.2.2", "integer", 2)                      # cafAuthMethodRegTable: dot1x registered
    add(CAF + ".1.1.2.1.2.3", "integer", 3)                      # and MAB
    ports = spec.get("ports", {})
    for n in range(1, 25):
        idx = 7 + n
        add(f".1.3.6.1.2.1.2.2.1.3.{idx}", "integer", 6)
        add(f".1.3.6.1.2.1.2.2.1.7.{idx}", "integer", 1)
        add(f".1.3.6.1.2.1.2.2.1.8.{idx}", "integer", 1)
        add(f".1.3.6.1.2.1.31.1.1.1.1.{idx}", "string", f"Gi1/0/{n}")
        add(f".1.3.6.1.2.1.31.1.1.1.18.{idx}", "string", "uplink" if n == 24 else "")
        p = ports.get(str(n), {})
        add(f"{CAF}.1.2.1.1.3.{idx}", "integer", 3)                                   # multi-auth
        add(f"{CAF}.1.2.1.1.4.{idx}", "integer", 1 if p.get("open") else 2)           # pre-auth open access
        add(f"{CAF}.1.2.1.1.5.{idx}", "integer", p.get("control", 3 if n == 24 else 2))  # the uplink isn't authenticated
    add(".1.3.6.1.2.1.2.2.1.3.100", "integer", 53)              # Vlan1: not a port
    add(".1.3.6.1.2.1.31.1.1.1.1.100", "string", "Vl1")
    for i, s in enumerate(spec.get("sessions", [])):
        idx = 7 + s["port"]
        sid = f"0A0A0A0B0000{i:04d}00ABCDEF"
        sub = ".".join(str(b) for b in sid.encode())
        mac = " ".join(s["mac"].replace("-", ":").split(":"))
        add(f"{CAF}.1.4.1.1.2.{idx}.{sub}", "octet", mac)
        add(f"{CAF}.1.4.1.1.5.{idx}.{sub}", "integer", s.get("status", 6))
        add(f"{CAF}.1.4.1.1.6.{idx}.{sub}", "integer", 2)
        add(f"{CAF}.1.4.1.1.10.{idx}.{sub}", "string", s.get("user", ""))
        add(f"{CAF}.1.4.1.1.12.{idx}.{sub}", "string", "Critical Auth" if s.get("critical") else "Authentication Server")
        add(f"{CAF}.1.4.1.1.13.{idx}.{sub}", "gauge", s.get("critical", 0))
        add(f"{CAF}.1.4.1.1.14.{idx}.{sub}", "integer", s.get("vlan", 0))
        add(f"{CAF}.1.4.2.1.2.{idx}.{len(sid)}.{sub}.{METHODS[s.get('method', 'dot1x')]}", "integer", 4)
    for n, cause in spec.get("errdis", {}).items():
        add(f".1.3.6.1.4.1.9.9.548.1.3.1.1.2.{7 + int(n)}.0", "integer", cause)
    return rows


if __name__ == "__main__":
    print(json.dumps(build(json.loads(sys.argv[1]))))
