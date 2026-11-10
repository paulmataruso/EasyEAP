"""An HTTPS server with fixture.py's self-signed certificate (as install.sh's temporary one), for tls-pin.ps1: it answers
every GET with 200 "ok". Usage: tls_server.py <cert> <key> <port>."""
from __future__ import annotations

import http.server
import ssl
import sys


class Ok(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 — the stdlib's name
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args) -> None:
        pass


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
srv = http.server.ThreadingHTTPServer(("0.0.0.0", int(sys.argv[3])), Ok)  # noqa: S104 — a test container's own network
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
