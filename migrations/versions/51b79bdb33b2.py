""" Add impact, likelihood and confidence to Rule and Vulnerability

Revision ID: 51b79bdb33b2
Revises: 792cdb4dabcc
Create Date: 2023-02-17 22:23:37.859955

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '51b79bdb33b2'
down_revision = '792cdb4dabcc'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('Rule', sa.Column('likelihood', sa.String(), nullable=True))
    op.add_column('Rule', sa.Column('impact', sa.String(), nullable=True))
    op.add_column('Rule', sa.Column('confidence', sa.String(), nullable=True))
    op.add_column('Vulnerability', sa.Column('impact', sa.String(), nullable=True))
    op.add_column('Vulnerability', sa.Column('likelihood', sa.String(), nullable=True))
    op.add_column('Vulnerability', sa.Column('confidence', sa.String(), nullable=True))


def downgrade():
    op.drop_column('Vulnerability', 'confidence')
    op.drop_column('Vulnerability', 'likelihood')
    op.drop_column('Vulnerability', 'impact')
    op.drop_column('Rule', 'confidence')
    op.drop_column('Rule', 'impact')
    op.drop_column('Rule', 'likelihood')