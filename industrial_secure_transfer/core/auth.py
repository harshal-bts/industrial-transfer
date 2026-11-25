"""
core/auth.py
Salted Argon2id offline/local operator credential verification (AUTH-01):
- Uses Argon2id (via argon2-cffi if installed, or RFC 9106 / standard PBKDF2-HMAC-SHA512 hardened fallback
  when running in minimal sandboxed environments, while supporting full Argon2id hashes natively).
- Enforces account-level rate limiting, consecutive failure lockout policy, generic error responses,
  no password logging, and idle/absolute session expiration.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional, Set

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
    _HAS_ARGON2_CFFI = True
except ImportError:
    _HAS_ARGON2_CFFI = False


class AuthenticationError(Exception):
    """Generic authentication error (AUTH-01: never leaks whether username or password failed)."""


class SessionExpiredError(AuthenticationError):
    """Raised when an operator session is missing, expired, or idle-locked."""


VALID_OPERATOR_ROLES: Set[str] = {"OPERATOR", "ADMIN"}


@dataclass(frozen=True)
class AccountRecord:
    username: str
    password_hash: str
    role: str = "OPERATOR"  # "OPERATOR" or "ADMIN"
    disabled: bool = False
    expires_at_epoch: Optional[float] = None


@dataclass
class AccountLockoutState:
    failed_attempts: int = 0
    locked_until_epoch: float = 0.0
    last_attempt_epoch: float = 0.0


@dataclass
class OperatorSession:
    session_id: str
    username: str
    role: str
    created_at_epoch: float
    last_activity_epoch: float
    expires_at_epoch: float
    idle_timeout_seconds: float

    def is_valid(self, now: float) -> bool:
        if now >= self.expires_at_epoch:
            return False
        if (now - self.last_activity_epoch) >= self.idle_timeout_seconds:
            return False
        return True


def hash_password_argon2id(
    password: str,
    *,
    time_cost: int = 3,
    memory_cost_kib: int = 65536,
    parallelism: int = 4,
    salt: Optional[bytes] = None,
) -> str:
    """
    Hashes a plaintext password using salted Argon2id.
    If `argon2-cffi` is installed, emits a standard `$argon2id$v=19$...` PHC string.
    Otherwise uses cryptography's Argon2id KDF if available, or an explicitly tagged
    `$argon2id-sim-pbkdf2-sha512$` PHC format with 210,000 iterations so environments
    without the C extension still enforce strong salted slow hashing without failure.
    """
    if not password:
        raise ValueError("Password cannot be empty.")

    if _HAS_ARGON2_CFFI and salt is None:
        ph = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost_kib,
            parallelism=parallelism,
            hash_len=32,
            salt_len=16,
        )
        return ph.hash(password)

    # Check if cryptography provides Argon2id
    raw_salt = salt if salt is not None else os.urandom(16)
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        kdf = Argon2id(
            salt=raw_salt,
            length=32,
            iterations=time_cost,
            lanes=parallelism,
            memory_cost=memory_cost_kib,
        )
        derived = kdf.derive(password.encode("utf-8"))
        b64_salt = base64.b64encode(raw_salt).decode("ascii").rstrip("=")
        b64_hash = base64.b64encode(derived).decode("ascii").rstrip("=")
        return f"$argon2id$v=19$m={memory_cost_kib},t={time_cost},p={parallelism}${b64_salt}${b64_hash}"
    except ImportError:
        iterations = 210_000
        derived = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), raw_salt, iterations, dklen=32)
        b64_salt = base64.b64encode(raw_salt).decode("ascii")
        b64_hash = base64.b64encode(derived).decode("ascii")
        return f"$pbkdf2-sha512$i={iterations}${b64_salt}${b64_hash}"


def verify_password_hash(password: str, stored_hash: str) -> bool:
    """
    Constant-time verification of a password against a stored PHC hash string.
    """
    if not password or not stored_hash:
        return False

    if stored_hash.startswith("$argon2id$"):
        if _HAS_ARGON2_CFFI:
            ph = PasswordHasher()
            try:
                return ph.verify(stored_hash, password)
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                return False
        try:
            from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
            parts = stored_hash.split("$")
            # ['', 'argon2id', 'v=19', 'm=65536,t=3,p=4', '<salt>', '<hash>']
            if len(parts) != 6:
                return False
            params = dict(kv.split("=") for kv in parts[3].split(","))
            m_cost = int(params["m"])
            t_cost = int(params["t"])
            p_lanes = int(params["p"])
            salt_b64 = parts[4] + "=" * ((4 - len(parts[4]) % 4) % 4)
            hash_b64 = parts[5] + "=" * ((4 - len(parts[5]) % 4) % 4)
            raw_salt = base64.b64decode(salt_b64)
            expected = base64.b64decode(hash_b64)
            kdf = Argon2id(
                salt=raw_salt,
                length=len(expected),
                iterations=t_cost,
                lanes=p_lanes,
                memory_cost=m_cost,
            )
            derived = kdf.derive(password.encode("utf-8"))
            return hmac.compare_digest(derived, expected)
        except Exception:
            return False

    if stored_hash.startswith("$pbkdf2-sha512$"):
        try:
            parts = stored_hash.split("$")
            if len(parts) != 5:
                return False
            iterations = int(parts[2].split("=")[1])
            raw_salt = base64.b64decode(parts[3])
            expected = base64.b64decode(parts[4])
            derived = hashlib.pbkdf2_hmac(
                "sha512", password.encode("utf-8"), raw_salt, iterations, dklen=len(expected)
            )
            return hmac.compare_digest(derived, expected)
        except Exception:
            return False

    return False


# Dummy precomputed hash used to equalize timing when a username does not exist
_DUMMY_HASH = hash_password_argon2id("dummy-constant-time-equalizer-password", time_cost=2, memory_cost_kib=16384)


class LocalAuthenticator:
    """
    Manages operator authentication, account lockout, rate limiting, and session expiration.
    Note: Even ADMIN role accounts cannot bypass safety gates (SAF-02).
    """

    def __init__(
        self,
        accounts: Dict[str, AccountRecord],
        *,
        max_failed_attempts: int = 5,
        lockout_duration_seconds: float = 300.0,
        min_attempt_interval_seconds: float = 0.5,
        session_ttl_seconds: float = 3600.0,
        idle_timeout_seconds: float = 900.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._accounts: Dict[str, AccountRecord] = dict(accounts)
        self._lockouts: Dict[str, AccountLockoutState] = {}
        self._sessions: Dict[str, OperatorSession] = {}
        self._max_failed_attempts = max(1, max_failed_attempts)
        self._lockout_duration = max(1.0, lockout_duration_seconds)
        self._min_interval = max(0.0, min_attempt_interval_seconds)
        self._session_ttl = max(10.0, session_ttl_seconds)
        self._idle_timeout = max(5.0, idle_timeout_seconds)
        self._clock = clock

    def authenticate(self, username: str, password: str) -> OperatorSession:
        """
        Verifies operator credentials.
        Raises generic AuthenticationError on any failure, rate-limit hit, or lockout (AUTH-01, UI-01).
        Never logs or echoes the password.
        """
        now = self._clock()
        clean_user = (username or "").strip()
        state = self._lockouts.setdefault(clean_user, AccountLockoutState())

        # Check rate limit interval
        if state.last_attempt_epoch > 0 and (now - state.last_attempt_epoch) < self._min_interval:
            state.last_attempt_epoch = now
            raise AuthenticationError("Authentication failed or account temporarily restricted.")

        state.last_attempt_epoch = now

        # Check active lockout
        if now < state.locked_until_epoch:
            raise AuthenticationError("Authentication failed or account temporarily restricted.")

        record = self._accounts.get(clean_user)
        if record is None:
            # Equalize timing against username enumeration
            verify_password_hash(password or "invalid", _DUMMY_HASH)
            state.failed_attempts += 1
            if state.failed_attempts >= self._max_failed_attempts:
                state.locked_until_epoch = now + self._lockout_duration
            raise AuthenticationError("Authentication failed or account temporarily restricted.")

        if record.disabled or (record.expires_at_epoch is not None and now >= record.expires_at_epoch):
            verify_password_hash(password or "invalid", _DUMMY_HASH)
            raise AuthenticationError("Authentication failed or account temporarily restricted.")

        if record.role not in VALID_OPERATOR_ROLES:
            raise AuthenticationError("Authentication failed or account temporarily restricted.")

        if not verify_password_hash(password, record.password_hash):
            state.failed_attempts += 1
            if state.failed_attempts >= self._max_failed_attempts:
                state.locked_until_epoch = now + self._lockout_duration
            raise AuthenticationError("Authentication failed or account temporarily restricted.")

        # Successful authentication resets failed attempt counter
        state.failed_attempts = 0
        state.locked_until_epoch = 0.0

        session = OperatorSession(
            session_id=f"SES-{uuid.uuid4().hex[:16].upper()}",
            username=record.username,
            role=record.role,
            created_at_epoch=now,
            last_activity_epoch=now,
            expires_at_epoch=now + self._session_ttl,
            idle_timeout_seconds=self._idle_timeout,
        )
        self._sessions[session.session_id] = session
        return session

    def validate_session(self, session_id: str, *, touch: bool = True) -> OperatorSession:
        """
        Validates that `session_id` exists and has not expired or timed out due to inactivity.
        """
        now = self._clock()
        session = self._sessions.get(session_id)
        if session is None or not session.is_valid(now):
            if session is not None:
                self._sessions.pop(session_id, None)
            raise SessionExpiredError("Operator session has expired or locked due to inactivity. Please re-authenticate.")

        if touch:
            session.last_activity_epoch = now
        return session

    def revoke_session(self, session_id: str) -> None:
        """Explicitly logs out / invalidates an active session."""
        self._sessions.pop(session_id, None)

    def is_account_locked(self, username: str) -> bool:
        """Returns True if the username is currently in a lockout window."""
        now = self._clock()
        state = self._lockouts.get(username.strip())
        return bool(state and now < state.locked_until_epoch)
