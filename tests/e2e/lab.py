"""Host-side helpers for run.sh (stdlib only): unpack the provisioning JSON, check monitoring events."""
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


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "unpack":
        unpack(sys.argv[2])
    elif cmd == "has-reason":
        sys.exit(has_reason(sys.argv[2], sys.argv[3]))
    elif cmd == "now":
        print(time.time())
