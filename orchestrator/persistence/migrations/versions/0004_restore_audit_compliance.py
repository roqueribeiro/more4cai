"""restore audit_log table and compliance fields

Reverte parcialmente a migration 0002. Reintroduz:
- Tabela `audit_log` (append-only via trigger Postgres)
- Coluna `scans.authorization_ref`

A migration 0002 removeu esses artefatos prematuramente, antes do feature de
gates de compliance ser implementado. Esta migration os traz de volta pra
suportar os gates de v0.1.x sem rebobinar o histórico (mantém 0002 + 0003).

contains_pci NAO eh reintroduzido — contains_pii cobre o caso de uso.

Revision ID: 0004
Revises: 0003
Create Date: 2026-05-12
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Recria audit_log
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("actor", sa.String(), nullable=True, index=True),
        sa.Column("action", sa.String(), nullable=False, index=True),
        sa.Column("resource_type", sa.String(), nullable=True),
        sa.Column("resource_id", sa.Uuid(), nullable=True, index=True),
        sa.Column("authorization_ref", sa.String(), nullable=True, index=True),
        sa.Column("request_hash", sa.String(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
    )

    # 2. Reintroduz authorization_ref em scans
    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("authorization_ref", sa.String(), nullable=True))
    op.create_index("ix_scans_authorization_ref", "scans", ["authorization_ref"], unique=False)

    # 3. Trigger Postgres pra append-only.
    # asyncpg nao aceita multi-statement: statements separados.
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            "CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$ "
            "BEGIN RAISE EXCEPTION 'audit_log is append-only'; END $$ LANGUAGE plpgsql"
        )
        op.execute(
            "CREATE TRIGGER audit_log_no_update "
            "BEFORE UPDATE OR DELETE ON audit_log "
            "FOR EACH ROW EXECUTE FUNCTION audit_log_immutable()"
        )


def downgrade() -> None:
    """downgrade nao suportado: dados de audit_log seriam perdidos."""
    raise NotImplementedError("downgrade nao suportado: removeria audit_log com dados imutaveis.")
