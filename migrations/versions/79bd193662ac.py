"""Add username and token in RuleRepository

Revision ID: 79bd193662ac
Revises: ae326ad9794d
Create Date: 2025-01-30 15:09:28.216768

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '79bd193662ac'
down_revision = 'ae326ad9794d'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('RuleRepository', schema=None) as batch_op:
        batch_op.add_column(sa.Column('username', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('token', sa.String(), nullable=True))


def downgrade():
    with op.batch_alter_table('RuleRepository', schema=None) as batch_op:
        batch_op.drop_column('token')
        batch_op.drop_column('username')

