"""Password hashing helpers for dashboard local accounts (design.md D10 / 10.2).

argon2id via argon2-cffi. Shared by dashboard-api and the admin bootstrap job
so both use one implementation and one parameter set.
"""
from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError

# Design Section 10.2.3: time_cost=3, memory_cost=65536 KiB, parallelism=4
# (argon2-cffi defaults; recorded so tests can assert them).
_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
)

# Re-export parameters for test assertions.
TIME_COST = 3
MEMORY_COST = 65536
PARALLELISM = 4


def hash_password(password: str) -> str:
    """Return an argon2id hash of ``password``."""
    return _HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Return True if ``password`` matches ``password_hash``."""
    try:
        return _HASHER.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False


def needs_rehash(password_hash: str) -> bool:
    """Return True if the hash should be upgraded to current parameters."""
    try:
        return _HASHER.check_needs_rehash(password_hash)
    except (InvalidHash, TypeError, ValueError):
        return True
