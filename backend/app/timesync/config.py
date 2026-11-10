"""The time settings the console edits (platform_settings['time']) and the status the time service reports
(platform_settings['time_status']).

EasyEAP's logs, sessions, certificates and Kerberos all take their time from the host's clock: every container shares
the host kernel's clock, and the database stamps rows with it. Keeping that clock right is the host's chronyd's job;
these settings tell it which servers to use.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

CONFIG_KEY, STATUS_KEY = "time", "time_status"
MAX_SERVERS = 8
# Warn past WARN_OFFSET; critical past CRIT_OFFSET (seconds). Kerberos refuses 5 minutes of skew; TOTP codes last 30
# seconds; logs from different systems stop lining up long before either.
WARN_OFFSET, CRIT_OFFSET = 0.1, 1.0
STALE_SECONDS = 180   # the service reports every 30 seconds
_UNSAFE = re.compile(r"[\s\x00-\x1f\x7f%\[\]]")
_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


class Server(BaseModel):
    address: str = Field(min_length=1, max_length=253)
    kind: Literal["server", "pool"] = "server"
    iburst: bool = True
    nts: bool = False
    prefer: bool = False

    @field_validator("address")
    @classmethod
    def _address(cls, v: str) -> str:
        """A name or an address and nothing else: it becomes a word in a chrony.conf line, so no whitespace, control
        character or IPv6 zone (`%…`, which ipaddress accepts with anything after it) can get through."""
        v = v.strip()
        if v.startswith("[") and v.endswith("]"):
            v = v[1:-1]
        if _UNSAFE.search(v):
            raise ValueError("Enter a host name or IP address, without a scheme or port.")
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            if not _HOST.fullmatch(v) or v.replace(".", "").isdigit():
                raise ValueError("Enter a host name or IP address, without a scheme or port.") from None
            return v.lower()
        if ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local:
            raise ValueError("Enter the address of an NTP server.")
        return str(ip)

    @model_validator(mode="after")
    def _pool(self) -> Server:
        if self.kind == "pool" and _is_ip(self.address):
            raise ValueError("A pool is a name that resolves to several servers: enter a host name, or choose Server.")
        return self

    def directive(self) -> str:
        """The chrony.conf line (chrony.conf(5): server and pool directives)."""
        opts = [o for o, on in (("iburst", self.iburst), ("nts", self.nts), ("prefer", self.prefer)) if on]
        return " ".join([self.kind, self.address, *opts])


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _check(servers: list[Server], only_these: bool) -> None:
    seen = set()
    for x in servers:
        if x.address in seen:
            raise ValueError(f"{x.address} is listed twice.")
        seen.add(x.address)
    if only_these and not servers:
        raise ValueError("Add at least one server before using only these servers.")


class SettingsIn(BaseModel):
    """What the console sends: validated here, so a mistake comes back as a 422 naming it."""
    servers: list[Server] = Field(default_factory=list, max_length=MAX_SERVERS)
    only_these: bool = False

    @model_validator(mode="after")
    def _valid(self) -> SettingsIn:
        _check(self.servers, self.only_these)
        return self


class TimeSettings(SettingsIn):
    revision: int = 0
    updated_at: str | None = None
    updated_by: str | None = None


def load(s: Any) -> TimeSettings:
    """The saved settings. A saved value that no longer validates raises (the time service then keeps steering chronyd
    with what it had) instead of reading as "no servers", which would remove them from the host."""
    from app import models as m
    row = s.get(m.PlatformSetting, CONFIG_KEY)
    return TimeSettings.model_validate(row.value) if row and row.value else TimeSettings()


def load_for_display(s: Any) -> TimeSettings:
    """load(), but an invalid saved value reads as empty (the console and health check, which can then replace it)."""
    try:
        return load(s)
    except ValueError:
        return TimeSettings()


def save(s: Any, body: SettingsIn, actor: str) -> TimeSettings:
    from app import models as m
    cur = load_for_display(s)
    new = TimeSettings(servers=body.servers, only_these=body.only_these, revision=cur.revision + 1,
                       updated_at=datetime.now(UTC).isoformat(), updated_by=actor)
    row = s.get(m.PlatformSetting, CONFIG_KEY) or m.PlatformSetting(key=CONFIG_KEY, value={})
    row.value = new.model_dump()
    s.add(row)
    return new


def assess(st: dict[str, Any], settings: TimeSettings) -> tuple[str, str]:
    """(tone, one line) for the health check and the log: valid, warn or crit."""
    off = st.get("offset")
    if st["mode"] == "chrony" and st.get("problem"):   # chronyd there but not answering: the kernel says how the clock is
        if st.get("kernel_synchronised") is False:
            return "crit", f"the clock isn't synchronised, and {st['problem'][:1].lower()}{st['problem'][1:]}"
        return "warn", st["problem"]
    if st["mode"] == "chrony":
        if not st.get("synchronised"):
            return "crit", "the clock isn't synchronised: chronyd has no usable NTP server"
    elif st.get("kernel_synchronised") is False:
        return "crit", "the clock isn't synchronised: no time daemon on the host is keeping it"
    if off is not None and abs(off) >= CRIT_OFFSET:
        return "crit", f"the clock is {abs(off):.2f} s {'fast' if off > 0 else 'slow'}"
    if off is not None and abs(off) >= WARN_OFFSET:
        return "warn", f"the clock is {abs(off) * 1000:.0f} ms {'fast' if off > 0 else 'slow'}"
    if st.get("apply_error"):
        return "warn", f"EasyEAP's NTP servers aren't applied: {st['apply_error']}"
    if st.get("select_error"):
        return "warn", st["select_error"]
    if st["mode"] == "sntp" and settings.servers:
        return "warn", "the host doesn't run chrony, so EasyEAP's NTP servers can't be applied"
    return "valid", "synchronised"


def load_status(s: Any) -> dict[str, Any] | None:
    from app import models as m
    row = s.get(m.PlatformSetting, STATUS_KEY)
    return dict(row.value) if row and row.value else None
