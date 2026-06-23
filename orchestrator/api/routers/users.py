"""Users router — gestão de usuários nomeados + papéis (RBAC). Admin-only.

Auth por **token por-usuário**: o token em claro só aparece UMA vez (na criação
ou na rotação) — guardamos apenas o hash. Toda mutação é auditada
(`user.create` / `user.deactivate` / `user.rotate_token`) com o `actor` real.
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlmodel import select

from orchestrator.api.deps import (
    Principal,
    SessionDep,
    require_permission,
    token_hash,
)
from orchestrator.audit import log_audit_event
from orchestrator.domain.roles import Permission, Role
from orchestrator.persistence.models import UserRow

router = APIRouter(prefix="/users", tags=["users"])

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Gate de RBAC reutilizado por todos os endpoints deste router.
_ADMIN = Depends(require_permission(Permission.USERS_MANAGE))


def _new_token() -> str:
    """Token por-usuário opaco (mostrado uma vez)."""
    return "cai_" + secrets.token_urlsafe(32)


class UserCreate(BaseModel):
    email: str
    name: str | None = None
    role: Role = Role.VIEWER

    @field_validator("email")
    @classmethod
    def _valid_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("e-mail inválido")
        return v


class RoleUpdate(BaseModel):
    role: Role


class UserOut(BaseModel):
    id: UUID
    email: str
    name: str | None
    role: str
    active: bool
    created_at: datetime
    last_login_at: datetime | None


class UserCreated(UserOut):
    api_token: str = Field(description="Token do usuário — mostrado UMA vez.")


def _to_out(u: UserRow) -> UserOut:
    return UserOut(
        id=u.id,
        email=u.email,
        name=u.name,
        role=u.role,
        active=u.active,
        created_at=u.created_at,
        last_login_at=u.last_login_at,
    )


@router.post("", response_model=UserCreated, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreate, session: SessionDep, principal: Principal = _ADMIN
) -> UserCreated:
    existing = (
        await session.exec(select(UserRow).where(UserRow.email == body.email))
    ).first()
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "e-mail já cadastrado")

    token = _new_token()
    user = UserRow(
        email=body.email,
        name=body.name,
        role=body.role.value,
        api_token_hash=token_hash(token),
    )
    session.add(user)
    await session.flush()
    await log_audit_event(
        session,
        action="user.create",
        actor=principal.email,
        resource_type="user",
        resource_id=user.id,
        metadata={"email": user.email, "role": user.role},
    )
    await session.commit()
    await session.refresh(user)
    return UserCreated(**_to_out(user).model_dump(), api_token=token)


@router.get("", response_model=list[UserOut])
async def list_users(session: SessionDep, _admin: Principal = _ADMIN) -> list[UserOut]:
    rows = (await session.exec(select(UserRow).order_by(UserRow.created_at))).all()
    return [_to_out(u) for u in rows]


@router.patch("/{user_id}/role", response_model=UserOut)
async def set_role(
    user_id: UUID,
    body: RoleUpdate,
    session: SessionDep,
    principal: Principal = _ADMIN,
) -> UserOut:
    user = await session.get(UserRow, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "usuário não encontrado")
    user.role = body.role.value
    session.add(user)
    await log_audit_event(
        session,
        action="user.set_role",
        actor=principal.email,
        resource_type="user",
        resource_id=user.id,
        metadata={"role": user.role},
    )
    await session.commit()
    await session.refresh(user)
    return _to_out(user)


@router.post("/{user_id}/deactivate", response_model=UserOut)
async def deactivate_user(
    user_id: UUID, session: SessionDep, principal: Principal = _ADMIN
) -> UserOut:
    user = await session.get(UserRow, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "usuário não encontrado")
    user.active = False
    session.add(user)
    await log_audit_event(
        session,
        action="user.deactivate",
        actor=principal.email,
        resource_type="user",
        resource_id=user.id,
    )
    await session.commit()
    await session.refresh(user)
    return _to_out(user)


@router.post("/{user_id}/rotate-token", response_model=UserCreated)
async def rotate_token(
    user_id: UUID, session: SessionDep, principal: Principal = _ADMIN
) -> UserCreated:
    user = await session.get(UserRow, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "usuário não encontrado")
    token = _new_token()
    user.api_token_hash = token_hash(token)
    session.add(user)
    await log_audit_event(
        session,
        action="user.rotate_token",
        actor=principal.email,
        resource_type="user",
        resource_id=user.id,
    )
    await session.commit()
    await session.refresh(user)
    return UserCreated(**_to_out(user).model_dump(), api_token=token)
