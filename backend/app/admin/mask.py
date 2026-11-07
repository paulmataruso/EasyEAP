"""Mask secrets in device commands before they are logged (docs/plans/device-admin.md §6).

TACACS+ command accounting carries every configuration command an administrator types, including the ones that set
passwords and keys (`username x secret 0 …`, `snmp-server community …`, `key 0 …`). The RADIUS agent masks them
before they reach its spool, and the API masks them again when it stores them.

This file is kept identical to services/radius/agent/tacmask.py (backend/tests/test_device_admin.py checks it).
"""
from __future__ import annotations

MASK = "*****"
# The token after one of these (and after any of the type words below) is a secret.
KEYWORDS = {"secret", "password", "key", "key-string", "pre-shared-key", "md5", "community", "auth", "priv", "wpa-psk",
            "server-key", "passphrase", "psk", "authentication-key", "ascii-key", "hex-key", "set-key", "password-encrypt",
            "area-password", "domain-password"}
# These take the rest of the line (IOS LINE arguments may contain spaces): `username bob password correct horse`.
REST_OF_LINE = {"password", "secret"}
# Words that sit between the keyword and the secret: encryption types, encodings, algorithms, key lengths.
TYPES = {"0", "5", "6", "7", "8", "9", "ascii", "hex", "unencrypted", "encrypted", "hidden", "sha", "sha-1", "sha-224",
         "sha-256", "sha-384", "sha-512", "md5", "aes", "des", "3des", "128", "192", "256"}
# Words that sit between one keyword and its secret only: `pre-shared-key local 0 <key>` (IKEv2 keyrings).
TYPES_AFTER = {"pre-shared-key": {"local", "remote"}}
# `key` and `password` are also ordinary words in a few commands; what follows them there isn't a secret.
NOT_SECRET = {"generate", "zeroize", "chain", "config-key", "export", "import", "pubkey-chain", "storage", "decrypt",
              "encrypt", "encryption", "rsa", "ec", "mypubkey", "<cr>", "recovery", "policy", "aaa", "length", "lifetime",
              "read", "write", "notify", "access", "context", "match"}


def _snmp_host(tokens: list[str]) -> list[str] | None:
    """`snmp-server host <addr> [vrf V] [informs|traps] [version 1|2c|3 [auth|noauth|priv]] <community> …`: the
    community sits after the options, not after a keyword. For version 3 it's a user name, kept."""
    if len(tokens) < 3 or tokens[0].lower() != "snmp-server" or tokens[1].lower() != "host":
        return None
    i, v3 = 3, False
    while i < len(tokens):
        t = tokens[i].lower()
        if t == "vrf" and i + 1 < len(tokens):
            i += 2
        elif t in ("informs", "traps"):
            i += 1
        elif t == "version" and i + 1 < len(tokens):
            v3 = tokens[i + 1] == "3"
            i += 2
            if v3 and i < len(tokens) and tokens[i].lower() in ("auth", "noauth", "priv"):
                i += 1
        else:
            break
    if v3 or i >= len(tokens) or tokens[i] == "<cr>":
        return tokens
    return [*tokens[:i], MASK, *tokens[i + 1:]]


def mask_command(cmd: str | None) -> str | None:
    if not cmd:
        return cmd
    tokens = cmd.split()
    host = _snmp_host(tokens)
    if host is not None:
        return " ".join(host)
    out: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        out.append(tok)
        i += 1
        low = tok.lower()
        if low == "text" and len(out) > 1 and out[-2].lower() == "authentication":
            low = "password"  # `standby 1 authentication text <secret>` (HSRP, VRRP, GLBP)
        if low not in KEYWORDS:
            continue
        if i < len(tokens) and tokens[i].lower() in NOT_SECRET:
            continue
        # Skip type words, and a key number before one (`authentication-key 1 md5 <key>`), but never the last token:
        # `password 12345 <cr>` masks 12345. A number after a type word is the secret: `auth sha 12345678 priv …`.
        extra = TYPES_AFTER.get(low, set())
        typed = False
        while i + 1 < len(tokens) and tokens[i + 1] != "<cr>":
            t = tokens[i].lower()
            if t in TYPES or t in extra or t in KEYWORDS:
                typed = True
            elif not (t.isdigit() and not typed and tokens[i + 1].lower() in TYPES):
                break
            out.append(tokens[i])
            i += 1
        if i < len(tokens) and tokens[i] != "<cr>":
            out.append(MASK)
            i += 1
            if low in REST_OF_LINE:
                while i < len(tokens) and tokens[i] != "<cr>":
                    i += 1
    return " ".join(out)
