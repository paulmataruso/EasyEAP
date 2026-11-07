"""Local device-administration accounts: password hashing and policy (docs/plans/device-admin.md §3, §6).

Hashes are stdlib scrypt (N=2^15, r=8, p=1) in the form `scrypt$<log2 N>$<r>$<p>$<salt b64>$<hash b64>`, so the
RADIUS agent verifies them with the Python standard library alone (services/radius/agent/tacacs.py mirrors
`verify`). The policy follows NIST SP 800-63B-4: length, not composition; a blocklist of common passwords.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re

LOG_N, R, P = 15, 8, 1
MAXMEM = 64 * 1024 * 1024
MIN_LENGTH = 15
MIN_LENGTH_WITH_TOTP = 8
MAX_LENGTH = 128
USERNAME = re.compile(r"^[a-z0-9._-]{1,64}$")

# Common and breached passwords long enough to pass the length rule, plus device defaults. Compared case-folded, and
# with digits and punctuation stripped from the end ("Password12345!" is "password").
_COMMON = {
    "password", "passw0rd", "p@ssw0rd", "p@ssword", "qwertyuiop", "qwertyuiopasdfghjkl", "1q2w3e4r5t6y", "1qaz2wsx3edc",
    "1qaz2wsx", "zaq12wsx", "iloveyou", "letmein", "welcome", "changeme", "administrator", "admin", "cisco", "ciscocisco",
    "sanfran", "default", "monkey", "dragon", "football", "baseball", "superman", "trustno1", "sunshine", "princess",
    "starwars", "whatever", "shadow", "master", "michael", "jennifer", "computer", "internet", "network", "networking",
    "switch", "router", "firewall", "wireless", "secret", "topsecret", "abcdefgh", "abcdefghijklmnop", "abcd1234",
    "aaaaaaaa", "asdfghjkl", "asdfasdf", "zxcvbnm", "qazwsxedc", "passwordpassword", "summer", "winter", "spring",
    "autumn", "january", "december", "company", "easyeap", "tacacs", "ubiquiti", "unifi", "fortinet", "paloalto",
}
_SEQUENCES = ("0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiopasdfghjklzxcvbnm")


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2 ** LOG_N, r=R, p=P, maxmem=MAXMEM, dklen=32)
    return f"scrypt${LOG_N}${R}${P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify(stored: str | None, password: str) -> bool:
    """Constant-time check; False for a malformed or missing hash."""
    try:
        alg, log_n, r, p, salt, want = (stored or "").split("$")
        if alg != "scrypt" or not (10 <= int(log_n) <= 20):
            return False
        dk = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=2 ** int(log_n), r=int(r), p=int(p), maxmem=MAXMEM, dklen=32)
        return hmac.compare_digest(dk, base64.b64decode(want))
    except (ValueError, TypeError):
        return False


def _core(password: str) -> str:
    return re.sub(r"[\d\W_]+$", "", password.lower())


def _repeats(x: str) -> bool:
    """"aaaa…", "abcabc…", "ciscocisco…": one short piece over and over."""
    return any(len(x) % n == 0 and x == x[:n] * (len(x) // n) for n in range(1, len(x) // 2 + 1))


def problems(password: str, *, username: str = "", totp: bool = False) -> list[str]:
    need = MIN_LENGTH_WITH_TOTP if totp else MIN_LENGTH
    out = []
    if len(password) < need:
        out.append(f"Use at least {need} characters" + ("." if totp else f" (or {MIN_LENGTH_WITH_TOTP} with an authenticator code)."))
    if len(password) > MAX_LENGTH:
        out.append(f"Use at most {MAX_LENGTH} characters.")
    if password != password.strip():
        out.append("Don't start or end the password with a space.")
    low = password.lower()
    if low in _COMMON or _core(password) in _COMMON:
        out.append("That's a common password. Choose a different one.")
    elif any(low in s or low in s[::-1] for s in _SEQUENCES) or len(set(low)) <= 2 or _repeats(_core(password) or low):
        out.append("That's too predictable. Choose a different one.")
    if username and len(username) >= 3 and username.lower() in low:
        out.append("Don't include the username.")
    return out
