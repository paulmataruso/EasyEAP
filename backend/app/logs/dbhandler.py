"""Write log records to system_logs from a background thread, so logging never waits on the database.

EasyEAP's own loggers (easyeap.*) are kept from INFO, everything else from WARNING. Messages are redacted before they
are queued. The queue is bounded: while the database is unavailable (or a restore is replacing it), the oldest records
are dropped first and the count of dropped records is reported once the database is back.
"""
from __future__ import annotations

import collections
import logging
import sys
import threading
import time
from datetime import UTC, datetime

from app.security.redact import redact

LEVELS = {logging.DEBUG: "debug", logging.INFO: "info", logging.WARNING: "warning", logging.ERROR: "error", logging.CRITICAL: "critical"}
MAX_QUEUE = 5000
MAX_MESSAGE = 4000
BATCH = 500
SOURCES = ("api", "worker", "radius-agent", "freeradius")


def wanted(record: logging.LogRecord) -> bool:
    if record.name == "easyeap" or record.name.startswith("easyeap."):
        return record.levelno >= logging.INFO
    return record.levelno >= logging.WARNING


def level_name(levelno: int) -> str:
    return LEVELS.get(levelno) or ("critical" if levelno > logging.CRITICAL else "debug" if levelno < logging.INFO else "info")


def write_rows(rows: list[dict]) -> None:
    from app import models as m
    from app.db import engine
    with engine().begin() as conn:
        conn.execute(m.SystemLog.__table__.insert(), rows)


class DatabaseLogHandler(logging.Handler):
    def __init__(self, source: str, *, interval: float = 2.0):
        super().__init__(level=logging.INFO)
        self.source = source
        self.interval = interval
        self.dropped = 0
        self._q: collections.deque[dict] = collections.deque(maxlen=MAX_QUEUE)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="system-log-writer", daemon=True)
        self._last_complaint = 0.0
        self._thread.start()

    def emit(self, record: logging.LogRecord) -> None:
        if threading.current_thread() is self._thread or not wanted(record):
            return
        try:
            msg = record.getMessage()
            if record.exc_info:
                msg = f"{msg}\n{logging.Formatter().formatException(record.exc_info)}"
            row = {"at": datetime.fromtimestamp(record.created, UTC), "level": level_name(record.levelno), "source": self.source,
                   "logger": record.name[:100], "message": redact(msg)[:MAX_MESSAGE]}
        except Exception:  # noqa: BLE001 — a broken record must never break the caller
            return
        with self._lock:
            if len(self._q) == MAX_QUEUE:
                self.dropped += 1
            self._q.append(row)

    def _take(self) -> list[dict]:
        with self._lock:
            return [self._q.popleft() for _ in range(min(len(self._q), BATCH))]

    def _requeue(self, rows: list[dict]) -> None:
        with self._lock:
            room = MAX_QUEUE - len(self._q)
            keep = rows[-room:] if room > 0 else []
            self.dropped += len(rows) - len(keep)
            self._q.extendleft(reversed(keep))

    def flush(self) -> None:
        """Write everything queued now (used at shutdown and by tests)."""
        while True:
            rows = self._take()
            if not rows:
                return
            try:
                write_rows(rows)
            except Exception:  # noqa: BLE001
                self._requeue(rows)
                return

    def _run(self) -> None:
        from app.backup.engine import maintenance
        while not self._stop.wait(self.interval):
            if not self._q:
                continue
            try:
                if maintenance():
                    continue
            except Exception:  # noqa: BLE001, S112 — the state file is unreadable: try again next round
                continue
            rows = self._take()
            n = self.dropped
            if n:
                rows.insert(0, {"at": datetime.now(UTC), "level": "warning", "source": self.source, "logger": "easyeap.logs",
                                "message": f"{n} log messages were dropped while the database was unavailable."})
            try:
                write_rows(rows)
                with self._lock:
                    self.dropped -= n
            except Exception as exc:  # noqa: BLE001 — never log about logging; say so on stderr at most once a minute
                self._requeue([r for r in rows if r.get("logger") != "easyeap.logs"])
                if time.monotonic() - self._last_complaint > 60:
                    self._last_complaint = time.monotonic()
                    print(f"easyeap: system log not written yet ({type(exc).__name__}); will retry", file=sys.stderr)

    def close(self) -> None:
        self._stop.set()
        self.flush()
        super().close()


_installed: DatabaseLogHandler | None = None


def install(source: str) -> DatabaseLogHandler | None:
    """Attach the handler to the root logger once per process. Not in tests."""
    global _installed
    from app.config import get_settings
    if _installed is not None or get_settings().environment == "test":
        return _installed
    _installed = DatabaseLogHandler(source)
    logging.getLogger().addHandler(_installed)
    return _installed
