"""Add progress and progress_updated_on in Analysis

Revision ID: ae326ad9794d
Revises: c61e3fbc1e31
Create Date: 2025-01-29 10:56:40.111941

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ae326ad9794d'
down_revision = 'c61e3fbc1e31'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('Analysis', schema=None) as batch_op:
        batch_op.add_column(sa.Column('progress', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('progress_updated_on', sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table('Analysis', schema=None) as batch_op:
        batch_op.drop_column('progress_updated_on')
        batch_op.drop_column('progress')
