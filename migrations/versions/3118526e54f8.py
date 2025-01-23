"""Add malicious insights in VulnerableDependency

Revision ID: 3118526e54f8
Revises: 8ba6283fc95d
Create Date: 2024-09-30 17:18:25.158354

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3118526e54f8'
down_revision = '8ba6283fc95d'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('VulnerableDependency', schema=None) as batch_op:
        batch_op.add_column(sa.Column('direct_usage', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('malicious', sa.Boolean(), nullable=True))
        batch_op.drop_column('indirect')
        batch_op.drop_column('direct')
        batch_op.drop_column('has_exploit')



def downgrade():
    with op.batch_alter_table('VulnerableDependency', schema=None) as batch_op:
        batch_op.add_column(sa.Column('has_exploit', sa.BOOLEAN(), nullable=True))
        batch_op.add_column(sa.Column('direct', sa.BOOLEAN(), nullable=True))
        batch_op.add_column(sa.Column('indirect', sa.BOOLEAN(), nullable=True))
        batch_op.drop_column('malicious')
        batch_op.drop_column('direct_usage')

