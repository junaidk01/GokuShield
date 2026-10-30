"""add remediation_actions table (approval queue)

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-11

"""
from alembic import op
import sqlalchemy as sa

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'remediation_actions',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('scan_id', sa.Integer, sa.ForeignKey('scans.id'), nullable=False, index=True),
        sa.Column('finding_index', sa.Integer, nullable=False),
        sa.Column('check_name', sa.String(255), nullable=False, index=True),
        sa.Column('severity', sa.String(20)),
        sa.Column('suggested_action', sa.Text, nullable=False),
        sa.Column('owasp_category', sa.String(100)),
        sa.Column('status', sa.String(20), nullable=False, server_default='pending', index=True),
        sa.Column('reviewed_by_user_id', sa.Integer, sa.ForeignKey('users.id'), nullable=True),
        sa.Column('reviewed_at', sa.DateTime),
        sa.Column('review_notes', sa.Text),
        sa.Column('created_at', sa.DateTime, nullable=False, index=True),
    )


def downgrade():
    op.drop_table('remediation_actions')
