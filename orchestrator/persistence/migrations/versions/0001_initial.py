"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-04-29
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
import sqlmodel  # noqa: F401  (alembic uses repr for SQLModel types)

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "targets",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("asset_type", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False, index=True),
        sa.Column("label", sa.String(), nullable=True),
        sa.Column("criticality", sa.String(), nullable=False),
        sa.Column("contains_pii", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("contains_pci", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("metadata_json", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("target_id", sa.Uuid(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("state", sa.String(), nullable=False, index=True),
        sa.Column("profile", sa.String(), nullable=False),
        sa.Column("requested_scanners", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("options", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("authorization_ref", sa.String(), nullable=True, index=True),
        sa.Column("actor", sa.String(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("errors", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("report_path", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("scan_id", sa.Uuid(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("target_id", sa.Uuid(), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("deduped_key", sa.String(), nullable=False, index=True),
        sa.Column("source_tool", sa.String(), nullable=False, index=True),
        sa.Column("source_rule_id", sa.String(), nullable=True),
        sa.Column("vuln_id", sa.String(), nullable=True, index=True),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False, index=True),
        sa.Column("confidence", sa.String(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
    )

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

    op.create_table(
        "ai_runs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("scan_id", sa.Uuid(), sa.ForeignKey("scans.id"), nullable=True, index=True),
        sa.Column("purpose", sa.String(), nullable=False),
        sa.Column("model", sa.String(), nullable=False),
        sa.Column("prompt_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completion_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cache_creation_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cache_read_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("latency_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("estimated_cost_usd", sa.Float(), nullable=False, server_default="0"),
        sa.Column("finding_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("success", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # audit_log append-only via trigger (Postgres). SQLite ignora.
    # asyncpg não aceita multi-statement: chamadas separadas.
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
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;")
        op.execute("DROP FUNCTION IF EXISTS audit_log_immutable;")
    op.drop_table("ai_runs")
    op.drop_table("audit_log")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("targets")
