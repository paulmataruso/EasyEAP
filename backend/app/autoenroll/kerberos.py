"""Kerberos for Group Policy autoenrollment (docs/plans/gpo-autoenrollment.md §2.2).

Windows authenticates to the policy and enrollment services with HTTP Negotiate. EasyEAP accepts the ticket with the
tenant's keytab (a service account with the SPN HTTP/<console host> in the tenant's AD); it never talks to a KDC.
Only Kerberos is accepted: an NTLM token means the PC couldn't get a ticket, and that's reported, not accepted.

The keytab lives encrypted in the database. To hand it to MIT Kerberos it's written, 0600, to a tmpfs directory that
only this process' user can read, named by its hash; the replay cache is there too.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path

RUNTIME_DIR = Path(os.environ.get("EASYEAP_KRB_DIR", "/dev/shm/easyeap-krb"))  # noqa: S108 — tmpfs: keytabs never touch disk

ENCTYPES = {17: "aes128-cts-hmac-sha1-96", 18: "aes256-cts-hmac-sha1-96", 19: "aes128-cts-hmac-sha256-128",
            20: "aes256-cts-hmac-sha384-192", 23: "rc4-hmac", 3: "des-cbc-md5", 1: "des-cbc-crc"}
AES = {17, 18, 19, 20}


class KerberosError(Exception):
    """`code` says what went wrong for the console's request log: ntlm | invalid | keytab | realm | not_kerberos |
    binding."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ── Keytabs ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class KeytabEntry:
    principal: str  # HTTP/easyeap.example.com
    realm: str      # CORP.EXAMPLE
    kvno: int
    enctype: int

    @property
    def enctype_name(self) -> str:
        return ENCTYPES.get(self.enctype, str(self.enctype))


def parse_keytab(data: bytes) -> list[KeytabEntry]:
    """Read an MIT keytab (version 0x0502, as ktpass and samba-tool write it). Raises ValueError if it isn't one."""
    return [e for e, _ in _records(data)]


def for_host(data: bytes, host: str) -> bytes:
    """The keytab cut down to its keys for HTTP/<host>. Accepting with no name, MIT tries every key in the keytab, so
    any other key in it (another service's, or krbtgt in a whole-domain export) would let EasyEAP accept tickets
    for that service too."""
    want = f"HTTP/{host}".lower()
    kept = [raw for e, raw in _records(data) if e.principal.lower() == want]
    return data[:2] + b"".join(struct.pack(">i", len(raw)) + raw for raw in kept)


def upload_problem(entries: list[KeytabEntry]) -> str | None:
    """A keytab EasyEAP mustn't even store."""
    if any(e.principal.lower().startswith("krbtgt/") for e in entries):
        return ("This keytab holds the domain's krbtgt key: it's an export of the whole domain, which is as sensitive as the "
                "domain itself. Delete it securely, and make one for EasyEAP's name only with the service-account script.")
    return None


def _records(data: bytes) -> list[tuple[KeytabEntry, bytes]]:
    if len(data) < 2 or data[0] != 5 or data[1] not in (1, 2):
        raise ValueError("This isn't a keytab file (it should start with 0x0502).")
    v1 = data[1] == 1
    pos, out = 2, []

    def counted(buf: bytes, i: int) -> tuple[bytes, int]:
        (n,) = struct.unpack_from(">H", buf, i)
        if i + 2 + n > len(buf):
            raise ValueError("The keytab is truncated.")
        return buf[i + 2:i + 2 + n], i + 2 + n

    while pos + 4 <= len(data):
        (size,) = struct.unpack_from(">i", data, pos)
        pos += 4
        if size < 0:  # a deleted entry
            pos += -size
            continue
        if size == 0:  # padding at the end
            break
        if pos + size > len(data):
            raise ValueError("The keytab is truncated (an incomplete upload?).")
        e, i = data[pos:pos + size], 0
        pos += size
        try:
            (ncomp,) = struct.unpack_from(">H", e, i)
            i += 2
            if v1:
                ncomp -= 1
            realm, i = counted(e, i)
            comps = []
            for _ in range(ncomp):
                c, i = counted(e, i)
                comps.append(c.decode("utf-8", "replace"))
            if not v1:
                i += 4  # name type
            i += 4  # timestamp
            kvno = e[i]
            i += 1
            (etype,) = struct.unpack_from(">H", e, i)
            i += 2
            _key, i = counted(e, i)
            if len(e) - i >= 4:
                (kvno32,) = struct.unpack_from(">I", e, i)
                if kvno32:
                    kvno = kvno32
        except (struct.error, IndexError) as exc:
            raise ValueError("The keytab is damaged.") from exc
        out.append((KeytabEntry("/".join(comps), realm.decode("utf-8", "replace"), kvno, etype), e))
    if not out:
        raise ValueError("The keytab has no keys.")
    return out


def summarize(entries: list[KeytabEntry], host: str) -> dict:
    """What the console shows, and what's wrong with it for HTTP/<host>."""
    want = f"HTTP/{host}".lower()
    mine = [e for e in entries if e.principal.lower() == want]
    problems = []
    if not mine:
        names = sorted({f"{e.principal}@{e.realm}" for e in entries})
        problems.append(f"It has no key for HTTP/{host} (it has {', '.join(names)}). Make it for that name: Windows asks for a "
                        "ticket to the name in the policy URL.")
    elif not any(e.enctype in AES for e in mine):
        problems.append("It has no AES key, only " + ", ".join(sorted({e.enctype_name for e in mine})) + ", and EasyEAP accepts "
                        "AES tickets only (Windows is retiring RC4). Allow AES on the service account and make the keytab "
                        "again: the service-account script does both (Windows: ktpass -crypto AES256-SHA1; Samba: "
                        "msDS-SupportedEncryptionTypes 24 before samba-tool domain exportkeytab).")
    realms = sorted({e.realm for e in mine})
    if len(realms) > 1:
        problems.append(f"It has keys for HTTP/{host} in several realms ({', '.join(realms)}); keep one tenant's realm.")
    latest = max((e.kvno for e in mine), default=0)
    return {"principal": f"HTTP/{host}@{realms[0]}" if len(realms) == 1 else None, "realm": realms[0] if len(realms) == 1 else None,
            "kvno": latest, "enctypes": sorted({e.enctype_name for e in mine if e.kvno == latest}), "problems": problems}


def forget(keytab: bytes) -> None:
    """Remove a replaced or deleted keytab's file from tmpfs (it's written again if it's still needed)."""
    _keytab_path(keytab).unlink(missing_ok=True)


def _keytab_path(keytab: bytes) -> Path:
    return RUNTIME_DIR / f"{hashlib.sha256(keytab).hexdigest()[:24]}.keytab"


def _keytab_file(keytab: bytes) -> Path:
    RUNTIME_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = _keytab_path(keytab)
    if not path.exists():
        fd, tmp = tempfile.mkstemp(dir=RUNTIME_DIR, prefix=".kt-")
        try:
            os.write(fd, keytab)
        finally:
            os.close(fd)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)  # same content from any worker, so the race is harmless
    return path


# ── Accepting a Negotiate token ──────────────────────────────────────────────

@dataclass(frozen=True)
class Caller:
    principal: str  # PC01$@CORP.EXAMPLE or nina@CORP.EXAMPLE
    name: str       # PC01$ / nina
    realm: str      # CORP.EXAMPLE
    reply: str | None  # base64 token for WWW-Authenticate (mutual authentication)
    channel_bound: bool = False  # the ticket's authenticator carried this TLS connection's channel binding

    @property
    def claims_computer(self) -> bool:
        """A NAME$ principal claims to be a computer; the directory confirms it (a user account can end in $ too)."""
        return self.name.endswith("$")


# Kerberos as the standard OID, and as Microsoft's (1.2.840.48018.1.2.2), which Windows offers first in SPNEGO.
KERBEROS_OIDS = {"1.2.840.113554.1.2.2", "1.2.840.48018.1.2.2"}


# ── Channel binding (EPA) ────────────────────────────────────────────────────

PROXY_CERT = Path(os.environ.get("EASYEAP_PROXY_CERT", "/etc/easyeap/proxy-tls.crt"))
_binding_cache: dict[str, tuple[tuple[float, int], bytes | None]] = {}


def tls_server_end_point(cert_der: bytes) -> bytes:
    """RFC 5929 4.1: the hash of the server's certificate, with the hash of its signature algorithm (SHA-256 when that
    is MD5 or SHA-1, or has no hash of its own)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    alg = x509.load_der_x509_certificate(cert_der).signature_hash_algorithm
    if alg is None or isinstance(alg, (hashes.MD5, hashes.SHA1)):
        alg = hashes.SHA256()
    h = hashes.Hash(alg)
    h.update(cert_der)
    return b"tls-server-end-point:" + h.finalize()


def proxy_binding(path: Path | None = None) -> bytes | None:
    """The channel binding of the certificate the proxy serves (the first one in its file), re-read when the file
    changes; None when it isn't available to the API (an installation whose compose file predates autoenrollment)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    path = path or PROXY_CERT
    try:
        st = path.stat()
    except OSError:
        return None
    key = str(path)
    cached = _binding_cache.get(key)
    if cached and cached[0] == (st.st_mtime, st.st_size):
        return cached[1]
    try:
        cert = x509.load_pem_x509_certificates(path.read_bytes())[0]
        value = tls_server_end_point(cert.public_bytes(serialization.Encoding.DER))
    except (OSError, ValueError, IndexError):
        value = None
    _binding_cache[key] = ((st.st_mtime, st.st_size), value)
    return value


def negotiate_token(header: str | None) -> bytes | None:
    if not header:
        return None
    scheme, _, value = header.strip().partition(" ")
    if scheme.lower() != "negotiate" or not value.strip():
        return None
    try:
        return base64.b64decode(value.strip(), validate=True)
    except ValueError:
        raise KerberosError("invalid", "The Negotiate token isn't valid base64.") from None


def accept(token: bytes, keytab: bytes, realms: list[str], *, binding: bytes | None = None) -> Caller:
    """Accept one SPNEGO/Kerberos token. With `binding` (the TLS channel binding), a ticket bound to another channel
    is refused and Caller.channel_bound says whether this one was bound. Raises KerberosError with a code for the
    request log."""
    if b"NTLMSSP\x00" in token:
        raise KerberosError("ntlm", "The PC sent NTLM, not Kerberos: it couldn't get a ticket for the service. Check the SPN "
                                    "(HTTP/<console host> on the EasyEAP service account, once in the forest) and that the policy "
                                    "URL uses that name, not an IP address or a CNAME.")
    import gssapi  # in the image (Dockerfile); imported here so the rest of the API doesn't need it

    path = _keytab_file(keytab)
    # python-gssapi can raise a failed step's error on the next attribute read, so everything is inside the try.
    try:
        creds = gssapi.Credentials(usage="accept", store={"keytab": f"FILE:{path}", "rcache": f"file2:{RUNTIME_DIR / 'rcache'}"})
        cb = gssapi.raw.ChannelBindings(application_data=binding) if binding else None
        ctx = gssapi.SecurityContext(creds=creds, usage="accept", channel_bindings=cb)
        out = ctx.step(token)
        complete, mech = ctx.complete, ctx.mech
        principal = str(ctx.initiator_name) if complete else ""
        bound = bool(binding) and complete and gssapi.RequirementFlag.channel_bound in ctx.actual_flags
    except gssapi.exceptions.GSSError as exc:
        if "channel binding" in _gss_text(exc).lower():
            raise KerberosError("binding", "The ticket was bound to a different TLS connection: something between the PC and "
                                           "EasyEAP ends TLS (a TLS-inspecting proxy), the ticket was relayed, or the proxy's "
                                           "certificate was replaced and easyeap-api wasn't restarted. Refused.") from None
        raise KerberosError("keytab" if _keytab_problem(exc) else "invalid", _gss_message(exc)) from None
    if not complete:
        raise KerberosError("invalid", "Kerberos needed another round trip, which Windows doesn't do for a ticket; refused.")
    if mech is None or mech.dotted_form not in KERBEROS_OIDS:
        raise KerberosError("not_kerberos", "The PC authenticated with something other than Kerberos; refused.")
    name, _, realm = principal.rpartition("@")
    if not name or not realm:
        raise KerberosError("invalid", f"Unexpected Kerberos name {principal!r}.")
    if realm.upper() not in {r.upper() for r in realms}:
        raise KerberosError("realm", f"{principal} is from realm {realm}, which isn't this tenant's ({', '.join(realms) or 'none set'}).")
    return Caller(principal=principal, name=name, realm=realm.upper(), reply=base64.b64encode(out).decode() if out else None,
                  channel_bound=bound)


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def clean_text(text: str, limit: int = 2000) -> str:
    """A message fit to store and show: GSS-API messages can carry NUL bytes, which Postgres refuses in text and JSON."""
    return _CONTROL.sub("", text).strip()[:limit]


def _gss_text(exc: Exception) -> str:
    gen = getattr(exc, "gen_message", None)
    return clean_text(gen() if callable(gen) else str(exc))


def _gss_message(exc: Exception) -> str:
    text = _gss_text(exc)
    if _keytab_problem(exc):
        return ("EasyEAP's keytab can't read the ticket: the service account's password or key version changed after the keytab "
                f"was made, or it was made without AES. Make a new keytab and upload it. ({text})")
    return f"Kerberos refused the ticket: {text}"


def _keytab_problem(exc: Exception) -> bool:
    text = _gss_text(exc).lower()
    return any(s in text for s in ("cannot decrypt", "no key table entry", "key version", "kvno", "wrong principal", "decrypt integrity"))
