"""Add source_files to VulnerableDependency

Revision ID: 8ba6283fc95d
Revises: 6c645b2e98ce
Create Date: 2024-09-30 11:35:39.709986

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8ba6283fc95d'
down_revision = '5655f7c23045'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('VulnerableDependency', schema=None) as batch_op:
        batch_op.add_column(sa.Column('source_files', sa.String(), nullable=True))


def downgrade():
    with op.batch_alter_table('VulnerableDependency', schema=None) as batch_op:
        batch_op.drop_column('source_files')
