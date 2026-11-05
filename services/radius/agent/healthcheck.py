"""Container health: FreeRADIUS answers Status-Server on the local status port (or has no configuration yet)."""
import os
import subprocess
import sys
from pathlib import Path

state = Path(os.environ.get("EASYEAP_RADIUS_STATE", "/var/lib/easyeap-radius"))
if not (state / "raddb" / "live" / "radiusd.conf").exists():
    sys.exit(0)  # waiting for first configuration from EasyEAP
p = subprocess.run(["radclient", "-t", "2", "-r", "1", "127.0.0.1:18121", "status", "easyeap-local-status"],
                   input="Message-Authenticator = 0x00\n", capture_output=True, text=True)
sys.exit(0 if "Access-Accept" in p.stdout else 1)
