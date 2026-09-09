"""
auth.py — Authentication utilities: password hashing, JWT token creation & verification.
Includes Anti-Hijacking Device Fingerprint binding.
"""

import os
import hashlib
from datetime import datetime, timedelta, timezone

import bcrypt
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from database import get_db
from models import User

SECRET_KEY = os.getenv("SECRET_KEY", "recon-tool-secret-key-change-in-production-2024")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

bearer_scheme = HTTPBearer(auto_error=False)



def hash_password(plain: str) -> str:
    """Hash a plain-text password using bcrypt. Bcrypt has a hard 72-byte limit."""
    pwd_bytes = plain.encode("utf-8")
    if len(pwd_bytes) > 72:
        raise HTTPException(status_code=400, detail="Password cannot be longer than 72 characters.")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plain-text password against a stored bcrypt hash."""
    try:
        pwd_bytes = plain.encode("utf-8")
        hashed_bytes = hashed.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hashed_bytes)
    except Exception:
        return False



def make_fingerprint(client_ip: str, user_agent: str) -> str:
    """Generate a SHA-256 fingerprint from client IP address and User-Agent string."""
    raw = f"{client_ip}:{user_agent[:128]}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def create_access_token(user_id: int, email: str, client_ip: str = "127.0.0.1", user_agent: str = "Unknown") -> str:
    """Create a signed JWT access token containing user id, email, and client device fingerprint."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    fp = make_fingerprint(client_ip, user_agent)
    payload = {
        "sub": str(user_id),
        "email": email,
        "exp": expire,
        "fp": fp,
        "ip": client_ip,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT. Raises HTTPException if invalid or expired."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
        )



def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    FastAPI dependency that extracts and validates the Bearer JWT,
    verifies client IP/User-Agent fingerprint binding to prevent session hijacking,
    and returns the corresponding User from the database.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    payload = decode_token(credentials.credentials)

    bound_fp = payload.get("fp")
    if bound_fp:
        current_ip = request.client.host if request.client else "127.0.0.1"
        current_ua = request.headers.get("user-agent", "Unknown")
        current_fp = make_fingerprint(current_ip, current_ua)
        if current_fp != bound_fp:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Security Violation: Token hijacked or replayed from an unauthorized IP/device.",
            )

    user = db.query(User).filter(User.id == int(payload["sub"])).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive.",
        )
    return user

