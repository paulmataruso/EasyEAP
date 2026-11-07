"""Host-side helpers for run.sh (stdlib only): unpack the provisioning JSON, check monitoring events, check JSON.

    … | lab.py check '<python expression over d>'   exit 0 if it is true for the JSON on stdin (test-authored expressions)
    … | lab.py has-event <epoch> '<expression over e>'  exit 0 if an event since then satisfies it
"""
import json
import os
import sys
import time
from datetime import datetime


def unpack(out_dir):
    d = json.load(sys.stdin)
    if "error" in d:
        sys.exit(f"provisioning failed: {d['error']}")

    def w(name, text):
        p = os.path.join(out_dir, name)
        with open(p, "w") as f:
            f.write(text)
        os.chmod(p, 0o644)  # read by the lab client container; lab-only keys, deleted at the end of the run

    w("ca.pem", d["ca_pem"])
    for user, c in d["certs"].items():
        w(f"{user}.pem", c["cert_pem"])
        w(f"{user}.key", c["key_pem"])
        print(f"    {user:6} serial {c['serial']}  CN={c['cn']}")
    w("secret", d["secret"])
    w("server", d["server_name"])
    print(f"    directory sync: {d['sync']}")
    print(f"    dave (disabled in AD) refused: {d['dave_enrollment_refused']}")


def has_reason(since_epoch, reason):
    """Exit 0 if a reject with `reason` was recorded at or after `since_epoch`."""
    events = json.load(sys.stdin)
    for e in events:
        at = datetime.fromisoformat(e["at"]).timestamp()
        if e["result"] == "reject" and e["reason"] == reason and at >= float(since_epoch) - 2:
            print(f"{reason}: {e['title']}")
            return 0
    seen = sorted({(e["result"], e["reason"]) for e in events if datetime.fromisoformat(e["at"]).timestamp() >= float(since_epoch) - 2}, key=str)
    print(f"no {reason} event yet (seen since start: {seen})")
    return 1


def has_event(since_epoch, expr):
    """Exit 0 if an event recorded at or after `since_epoch` satisfies `expr` (over e)."""
    events = json.load(sys.stdin)
    recent = [e for e in events if datetime.fromisoformat(e["at"]).timestamp() >= float(since_epoch) - 2]
    for e in recent:
        try:
            if eval(expr, {"__builtins__": {}, "str": str}, {"e": e}):  # noqa: S307 — test-authored
                return 0
        except (KeyError, TypeError):
            continue
    print(f"none matched (since start: {[{k: e.get(k) for k in ('result', 'reason', 'network', 'port', 'vlan', 'monitor')} for e in recent][:8]})")
    return 1


def check(expr):
    raw = sys.stdin.read()
    try:
        d = json.loads(raw)
        good = bool(eval(expr, {"__builtins__": {}, "any": any, "all": all, "len": len, "set": set, "sorted": sorted, "str": str, "next": next}, {"d": d}))  # noqa: S307 — test-authored
    except Exception as e:  # noqa: BLE001 — report any failure as a failed check
        good, raw = False, f"{type(e).__name__}: {e} in {raw[:600]}"
    if not good:
        print(raw[:1200])
    return 0 if good else 1


def check_script(script):
    """Like check, for several statements: asserts over d; an AssertionError's message is printed."""
    raw = sys.stdin.read()
    try:
        d = json.loads(raw)
        exec(script, {"__builtins__": {"any": any, "all": all, "len": len, "set": set, "sorted": sorted, "str": str, "next": next,  # noqa: S102 — test-authored
                                        "AssertionError": AssertionError}, "d": d})
        return 0
    except Exception as e:  # noqa: BLE001 — report any failure as a failed check
        print(f"{type(e).__name__}: {str(e)[:600]}")
        return 1


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "unpack":
        unpack(sys.argv[2])
    elif cmd == "has-reason":
        sys.exit(has_reason(sys.argv[2], sys.argv[3]))
    elif cmd == "now":
        print(time.time())
    elif cmd == "has-event":
        sys.exit(has_event(sys.argv[2], sys.argv[3]))
    elif cmd == "check-script":
        sys.exit(check_script(sys.argv[2]))
    elif cmd == "check":
        sys.exit(check(sys.argv[2]))
