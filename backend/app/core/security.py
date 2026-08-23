"""
ThreatLens AI — Security Utilities

Handles:
- Password hashing with bcrypt (via passlib)
- JWT access & refresh token creation/verification
- OAuth2 bearer token extraction dependency
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Union

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db

# ── Password Hashing ─────────────────────────────────────────────────────────
# bcrypt is the recommended algorithm — auto-upgrades deprecated hashes.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── OAuth2 Bearer Token Scheme ───────────────────────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# ─────────────────────────────────────────────────────────────────────────────
# Password Utilities
# ─────────────────────────────────────────────────────────────────────────────

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Return True if plain_password matches the stored hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return pwd_context.hash(password)


# ─────────────────────────────────────────────────────────────────────────────
# Token Creation
# ─────────────────────────────────────────────────────────────────────────────

def _create_token(data: dict, expires_delta: timedelta, token_type: str = "access") -> str:
    """Internal helper — creates a signed JWT with standard claims."""
    payload = data.copy()
    now = datetime.now(timezone.utc)
    payload.update({
        "iat": now,
        "exp": now + expires_delta,
        "type": token_type,
    })
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_access_token(subject: Union[str, int], extra: Optional[dict] = None) -> str:
    """Create a short-lived JWT access token."""
    data = {"sub": str(subject), **(extra or {})}
    return _create_token(
        data,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        token_type="access",
    )


def create_refresh_token(subject: Union[str, int]) -> str:
    """Create a long-lived JWT refresh token."""
    return _create_token(
        {"sub": str(subject)},
        expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        token_type="refresh",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Token Verification
# ─────────────────────────────────────────────────────────────────────────────

def decode_token(token: str, expected_type: str = "access") -> dict:
    """
    Decode and validate a JWT token.

    Raises HTTP 401 on any validation failure — never exposes internal errors.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        subject: Optional[str] = payload.get("sub")
        token_type: Optional[str] = payload.get("type")

        if subject is None:
            raise credentials_exception
        if token_type != expected_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token type. Expected '{expected_type}'",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload
    except JWTError:
        raise credentials_exception


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI Dependency — Current Authenticated User
# ─────────────────────────────────────────────────────────────────────────────

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
):
    """
    FastAPI dependency that extracts and validates the bearer token,
    then returns the associated User record from the database.

    Import and use as: `current_user = Depends(get_current_user)`
    """
    from app.models.user import User
    from sqlalchemy import select

    payload = decode_token(token, expected_type="access")
    user_id: str = payload.get("sub")

    result = await db.execute(select(User).where(User.id == int(user_id)))
    user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_current_admin(current_user=Depends(get_current_user)):
    """Restrict access to admin-only endpoints."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Admin role required.",
        )
    return current_user
