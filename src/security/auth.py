"""安全工作台的本地账号、密码哈希与短期 JWT。"""

import hashlib
import os
import re
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from core import settings
from security.repository import create_user, get_user, list_users, update_user

Role = Literal["ANALYST", "MANAGER", "ADMIN"]
bearer = HTTPBearer(auto_error=False)
router = APIRouter(prefix="/security/auth", tags=["安全账号"])


def _signing_key() -> str:
    configured = os.getenv("SECURITY_JWT_SECRET") or (
        settings.SECURITY_JWT_SECRET.get_secret_value() if settings.SECURITY_JWT_SECRET else None
    )
    if configured:
        if len(configured) < 32:
            raise RuntimeError("SECURITY_JWT_SECRET 至少需要 32 个字符")
        return configured
    path = Path(__file__).resolve().parents[2] / ".runtime-tools" / "security_jwt.key"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(secrets.token_urlsafe(48))
    return path.read_text(encoding="utf-8").strip()


def hash_password(password: str) -> str:
    """PBKDF2-SHA256 与随机盐；不保存或记录原始密码。"""
    if len(password) < 12 or len(password) > 256:
        raise ValueError("密码长度应为 12 到 256 个字符")
    salt = secrets.token_bytes(16)
    rounds = 600_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, rounds)
    return f"pbkdf2_sha256${rounds}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        method, rounds, salt, digest = encoded.split("$")
        if method != "pbkdf2_sha256" or not 100_000 <= int(rounds) <= 2_000_000:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds))
        return secrets.compare_digest(actual, bytes.fromhex(digest))
    except (ValueError, TypeError):
        return False


def issue_token(username: str) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": username,
            "iss": "security-investigation",
            "aud": "security-workbench",
            "iat": now,
            "exp": now + timedelta(hours=8),
        },
        _signing_key(),
        algorithm="HS256",
    )


def current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> dict:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="请先登录安全工作台")
    try:
        claims = jwt.decode(
            credentials.credentials,
            _signing_key(),
            algorithms=["HS256"],
            issuer="security-investigation",
            audience="security-workbench",
            options={"require": ["sub", "exp", "iat"]},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="登录已失效，请重新登录") from exc
    user = get_user(claims["sub"])
    if not user or not user["active"]:
        raise HTTPException(status_code=401, detail="账号不可用")
    return {key: value for key, value in user.items() if key != "password_hash"}


def require_manager(user: Annotated[dict, Depends(current_user)]) -> dict:
    if user["role"] not in {"MANAGER", "ADMIN"}:
        raise HTTPException(status_code=403, detail="需要主管或管理员权限")
    return user


def require_admin(user: Annotated[dict, Depends(current_user)]) -> dict:
    if user["role"] != "ADMIN":
        raise HTTPException(status_code=403, detail="需要管理员权限")
    return user


class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=256)
    role: Role = "ANALYST"


class UserUpdate(BaseModel):
    role: Role
    active: bool = True


@router.post("/login")
def login(request: LoginRequest) -> dict[str, str]:
    user = get_user(request.username)
    if (
        not user
        or not user["active"]
        or not verify_password(request.password, user["password_hash"])
    ):
        raise HTTPException(status_code=401, detail="账号或密码错误")
    return {
        "access_token": issue_token(user["username"]),
        "token_type": "bearer",
        "role": user["role"],
    }


@router.get("/me")
def me(user: Annotated[dict, Depends(current_user)]) -> dict:
    return user


@router.get("/users")
def users(_: Annotated[dict, Depends(require_admin)]) -> list[dict]:
    return list_users()


@router.post("/users", status_code=201)
def add_user(request: UserCreate, _: Annotated[dict, Depends(require_admin)]) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", request.username):
        raise HTTPException(
            status_code=422, detail="用户名只能包含英文字母、数字、点、下划线和连字符"
        )
    if get_user(request.username):
        raise HTTPException(status_code=409, detail="用户名已存在")
    return create_user(request.username, hash_password(request.password), request.role)


@router.patch("/users/{username}")
def change_user(
    username: str, request: UserUpdate, admin: Annotated[dict, Depends(require_admin)]
) -> dict:
    if username == admin["username"] and (not request.active or request.role != "ADMIN"):
        raise HTTPException(status_code=409, detail="不能停用或降级当前管理员账号")
    if not update_user(username, request.role, request.active):
        raise HTTPException(status_code=404, detail="用户不存在")
    user = get_user(username)
    return {key: value for key, value in user.items() if key != "password_hash"}
