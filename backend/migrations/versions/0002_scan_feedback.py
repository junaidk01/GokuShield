"""add scan_feedback table

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-10

"""
from alembic import op
import sqlalchemy as sa

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'scan_feedback',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('scan_id', sa.Integer, sa.ForeignKey('scans.id'), nullable=False, index=True),
        sa.Column('finding_index', sa.Integer, nullable=False),
        sa.Column('check_name', sa.String(255), nullable=False, index=True),
        sa.Column('is_true_positive', sa.Boolean, nullable=False),
        sa.Column('notes', sa.Text),
        sa.Column('submitted_by_user_id', sa.Integer, sa.ForeignKey('users.id'), nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False, index=True),
    )


def downgrade():
    op.drop_table('scan_feedback')
