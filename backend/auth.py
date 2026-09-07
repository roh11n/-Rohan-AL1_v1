"""JWT authentication + RBAC dependencies + in-memory throttling."""
import os
import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext

from db import db

SECRET_KEY = os.environ["JWT_SECRET_KEY"]
ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False


def create_access_token(subject: str, extra: dict | None = None) -> str:
    to_encode = {"sub": subject}
    if extra:
        to_encode.update(extra)
    to_encode["exp"] = datetime.now(timezone.utc) + timedelta(minutes=EXPIRE_MINUTES)
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def _decode(token: Optional[str]) -> dict:
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")


async def get_current_user(token: Optional[str] = Depends(oauth2_scheme)) -> dict:
    payload = await _decode(token)
    email = payload.get("sub")
    user = await db.users.find_one({"email": email})
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    if not user.get("active", True):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "User deactivated")
    user["id"] = str(user.get("id") or user.get("_id"))
    user.pop("hashed_password", None)
    user.pop("_id", None)
    return user


def require_roles(allowed: List[str]):
    async def _check(user: dict = Depends(get_current_user)) -> dict:
        if user.get("role") not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user

    return _check


# ---------- Login throttling (in-memory sliding window) ----------
_LOGIN_LOCK = threading.Lock()
_LOGIN_ATTEMPTS: dict[str, deque] = defaultdict(deque)  # email -> deque[timestamps of failed attempts]
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60  # 15 minutes


def _prune(dq: deque, window: float, now: float):
    while dq and (now - dq[0]) > window:
        dq.popleft()


def login_throttle_check(email: str) -> None:
    """Raise 429 if the caller has too many recent failed logins."""
    now = time.time()
    with _LOGIN_LOCK:
        dq = _LOGIN_ATTEMPTS[email.lower()]
        _prune(dq, LOGIN_WINDOW_SECONDS, now)
        if len(dq) >= LOGIN_MAX_ATTEMPTS:
            wait = int(LOGIN_WINDOW_SECONDS - (now - dq[0]))
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                                f"Too many failed attempts. Try again in {max(1, wait // 60)} minute(s).")


def login_throttle_record_failure(email: str) -> None:
    with _LOGIN_LOCK:
        _LOGIN_ATTEMPTS[email.lower()].append(time.time())


def login_throttle_reset(email: str) -> None:
    with _LOGIN_LOCK:
        _LOGIN_ATTEMPTS.pop(email.lower(), None)


# ---------- Per-user endpoint rate limiter (sliding window) ----------
_RL_LOCK = threading.Lock()
_RL_BUCKETS: dict[tuple[str, str], deque] = defaultdict(deque)


def enforce_rate_limit(user_email: str, bucket: str, limit: int, window_seconds: int) -> None:
    """Raise 429 if the user has exceeded `limit` events in the given window."""
    now = time.time()
    key = (user_email, bucket)
    with _RL_LOCK:
        dq = _RL_BUCKETS[key]
        _prune(dq, window_seconds, now)
        if len(dq) >= limit:
            wait = int(window_seconds - (now - dq[0]))
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                                f"Rate limit exceeded ({limit} per {window_seconds // 60} min). Retry in {max(1, wait)}s.")
        dq.append(now)
