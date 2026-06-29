"""add finding_status table (resolution workflow keyed by deduped_key)

Estado de resolução de cada problema (open/in_progress/resolved/false_positive/
wont_fix/risk_accepted) atrelado ao `deduped_key` (identidade determinística do
problema), pra SOBREVIVER re-scans — `findings` é write-once e um re-scan cria
novos rows com o mesmo `deduped_key`. Ver `orchestrator.persistence.models.
FindingStatusRow` + os endpoints `/findings/queue|summary|resolve`.

Revision ID: 0006
Revises: 0005
Create Date: 2026-06-29
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "finding_status",
        sa.Column("deduped_key", sa.String(), primary_key=True),
        sa.Column("status", sa.String(), nullable=False, server_default="open"),
        sa.Column("note", sa.String(), nullable=True),
        sa.Column("updated_by", sa.String(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_severity", sa.String(), nullable=True),
        sa.Column("last_title", sa.String(), nullable=True),
        sa.Column("target_value", sa.String(), nullable=True),
    )
    op.create_index("ix_finding_status_status", "finding_status", ["status"])
    op.create_index("ix_finding_status_updated_by", "finding_status", ["updated_by"])
    op.create_index("ix_finding_status_last_severity", "finding_status", ["last_severity"])
    op.create_index("ix_finding_status_target_value", "finding_status", ["target_value"])


def downgrade() -> None:
    op.drop_index("ix_finding_status_target_value", table_name="finding_status")
    op.drop_index("ix_finding_status_last_severity", table_name="finding_status")
    op.drop_index("ix_finding_status_updated_by", table_name="finding_status")
    op.drop_index("ix_finding_status_status", table_name="finding_status")
    op.drop_table("finding_status")
