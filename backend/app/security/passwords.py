"""Argon2id password hashing (OWASP parameters) and password policy."""
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2, hash_len=32, salt_len=16)
# Verified against when the account does not exist, so timing does not reveal valid emails.
_DUMMY_HASH = _hasher.hash("easyeap-timing-equaliser")

MIN_LENGTH = 12


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _hasher.check_needs_rehash(stored_hash)


def password_problems(password: str, email: str = "") -> list[str]:
    problems = []
    if len(password) < MIN_LENGTH:
        problems.append(f"Use at least {MIN_LENGTH} characters.")
    if email and email.split("@")[0].lower() in password.lower():
        problems.append("Don't include your email name in the password.")
    if len(set(password)) < 6:
        problems.append("Use a less repetitive password.")
    return problems
