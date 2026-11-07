"""pass_persist handler: serves /lab/data/dataset.json ([[oid, type, value], ...]) to snmpd, re-reading it on change."""
import json
import os
import sys

PATH = "/lab/data/dataset.json"
_rows, _mtime = [], None


def key(o):
    return tuple(int(x) for x in o.strip(".").split("."))


def rows():
    global _rows, _mtime
    try:
        mt = os.stat(PATH).st_mtime_ns
    except FileNotFoundError:
        return []
    if mt != _mtime:
        with open(PATH) as f:
            data = json.load(f)
        _rows = sorted(((key(o), t, v) for o, t, v in data), key=lambda r: r[0])
        _mtime = mt
    return _rows


def out(*lines):
    sys.stdout.write("\n".join(str(x) for x in lines) + "\n")
    sys.stdout.flush()


def main():
    while True:
        cmd = sys.stdin.readline()
        if not cmd:
            return
        cmd = cmd.strip()
        if cmd == "PING":
            out("PONG")
        elif cmd in ("get", "getnext"):
            want = key(sys.stdin.readline().strip())
            hit = None
            for o, t, v in rows():
                if (cmd == "get" and o == want) or (cmd == "getnext" and o > want):
                    hit = (o, t, v)
                    break
            if hit:
                out("." + ".".join(map(str, hit[0])), hit[1], hit[2])
            else:
                out("NONE")
        elif cmd == "set":
            sys.stdin.readline()
            sys.stdin.readline()
            out("not-writable")
        else:
            out("NONE")


main()
