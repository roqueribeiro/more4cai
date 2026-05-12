"""remove compliance fields and audit_log

Drop audit_log table and trigger; drop authorization_ref from scans;
drop contains_pci from targets. contains_pii MANTÉM (boa prática genérica).

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-29

"""
from typing import Sequence, Union

from alembic import op


revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()

    # 1. Drop trigger e function (Postgres). asyncpg não aceita multi-statement —
    # statements separados.
    if bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log")
        op.execute("DROP FUNCTION IF EXISTS audit_log_immutable")

    # 2. Drop tabela audit_log (depende dos índices)
    op.drop_table("audit_log")

    # 3. Drop colunas regulatórias
    with op.batch_alter_table("scans") as batch:
        batch.drop_column("authorization_ref")
    with op.batch_alter_table("targets") as batch:
        batch.drop_column("contains_pci")
    # contains_pii MANTÉM — útil pra rotear AI triage ao backend local.


def downgrade() -> None:
    raise NotImplementedError(
        "downgrade não suportado: dados de audit_log perdidos no upgrade."
    )
