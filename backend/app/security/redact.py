"""Logging filter that removes secrets. Defence in depth: code never logs secrets intentionally."""
import logging
import re

_PATTERNS = [
    re.compile(r"(?i)(password|passwd|secret|token|passphrase|bind_password|shared_secret|private_key|p12)(\"?\s*[:=]\s*\"?)([^\s\",}]+)"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"(?i)(authorization:\s*bearer\s+)\S+"),
    re.compile(r"(?i)(x-vault-token:\s*)\S+"),
]


def redact(text: str) -> str:
    text = _PATTERNS[0].sub(r"\1\2[REDACTED]", text)
    text = _PATTERNS[1].sub("[REDACTED PRIVATE KEY]", text)
    text = _PATTERNS[2].sub(r"\1[REDACTED]", text)
    return _PATTERNS[3].sub(r"\1[REDACTED]", text)


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = ()
        return True


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    for noisy in ("uvicorn.access",):
        logging.getLogger(noisy).addFilter(RedactingFilter())
