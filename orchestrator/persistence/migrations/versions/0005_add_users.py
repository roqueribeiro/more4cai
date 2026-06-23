"""add users table (RBAC + per-user tokens)

Introduz `users` — usuários nomeados com papel (RBAC) e token por-usuário
(hash SHA-256). O `APP_TOKEN` global continua válido como principal de serviço
(admin), então a integração RoqueShield (`X-API-Token`) NÃO quebra.

`idp_subject` fica reservado pro login OIDC/SSO (Fase 6).

Revision ID: 0005
Revises: 0004
Create Date: 2026-06-23
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("role", sa.String(), nullable=False, server_default="viewer"),
        sa.Column("api_token_hash", sa.String(), nullable=True),
        sa.Column("idp_subject", sa.String(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_role", "users", ["role"])
    op.create_index("ix_users_api_token_hash", "users", ["api_token_hash"], unique=True)
    op.create_index("ix_users_idp_subject", "users", ["idp_subject"])
    op.create_index("ix_users_active", "users", ["active"])


def downgrade() -> None:
    op.drop_index("ix_users_active", table_name="users")
    op.drop_index("ix_users_idp_subject", table_name="users")
    op.drop_index("ix_users_api_token_hash", table_name="users")
    op.drop_index("ix_users_role", table_name="users")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
