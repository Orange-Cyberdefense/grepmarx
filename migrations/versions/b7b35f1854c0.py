"""Add dependency_tree in VulnerableDependency

Revision ID: b7b35f1854c0
Revises: 3118526e54f8
Create Date: 2024-10-02 12:05:30.250140

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b7b35f1854c0'
down_revision = '3118526e54f8'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('VulnerableDependency', schema=None) as batch_op:
        batch_op.add_column(sa.Column('dependency_tree', sa.String(), nullable=True))



def downgrade():
    with op.batch_alter_table('VulnerableDependency', schema=None) as batch_op:
        batch_op.drop_column('dependency_tree')

