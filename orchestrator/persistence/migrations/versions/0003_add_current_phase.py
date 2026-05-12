"""add current_phase + phase_progress + raw_payload to scans/findings

Adiciona granularidade de fase pro pipeline (queued|nmap_running|zap_spider|
zap_passive|zap_active|dedup|ai_triage|persisting|reporting|done|failed) e
percentual de progresso quando aplicável.

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-29

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("current_phase", sa.String(), nullable=True))
        batch.add_column(sa.Column("phase_progress", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.drop_column("phase_progress")
        batch.drop_column("current_phase")
