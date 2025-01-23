"""Add status to occurence

Revision ID: 6201ea3d70cc
Revises: e391e32b3394
Create Date: 2024-02-23 09:56:24.233006

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6201ea3d70cc'
down_revision = 'e391e32b3394'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('Occurence', schema=None) as batch_op:
        batch_op.add_column(sa.Column('status', sa.Integer(), nullable=True))


def downgrade():
    with op.batch_alter_table('Occurence', schema=None) as batch_op:
        batch_op.drop_column('status')

