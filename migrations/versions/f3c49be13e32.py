"""Add vulnerability dataflow positions

Revision ID: f3c49be13e32
Revises: b7b35f1854c0
Create Date: 2024-12-16 15:47:39.123535

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f3c49be13e32'
down_revision = 'b7b35f1854c0'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('DataflowPosition',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('occurence_id', sa.Integer(), nullable=True),
    sa.Column('content', sa.String(), nullable=True),
    sa.Column('line_start', sa.Integer(), nullable=True),
    sa.Column('line_end', sa.Integer(), nullable=True),
    sa.Column('column_start', sa.Integer(), nullable=True),
    sa.Column('column_end', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['occurence_id'], ['Occurence.id'], ),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    op.drop_table('DataflowPosition')
