"""Dependency scan (SCA)

Revision ID: 792cdb4dabcc
Revises: c9af49fc09c4
Create Date: 2023-02-07 22:33:36.690251

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '792cdb4dabcc'
down_revision = 'c9af49fc09c4'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('VulnerableDependency',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('analysis_id', sa.Integer(), nullable=False),
    sa.Column('common_id', sa.String(), nullable=False),
    sa.Column('bom_ref', sa.String(), nullable=False),
    sa.Column('pkg_type', sa.String(), nullable=False),
    sa.Column('pkg_ref', sa.String(), nullable=False),
    sa.Column('pkg_name', sa.String(), nullable=False),
    sa.Column('source', sa.String(), nullable=False),
    sa.Column('severity', sa.String(), nullable=False),
    sa.Column('cvss_score', sa.String(), nullable=True),
    sa.Column('cvss_version', sa.String(), nullable=True),
    sa.Column('cwes', sa.String(), nullable=True),
    sa.Column('description', sa.String(), nullable=True),
    sa.Column('recommendation', sa.String(), nullable=True),
    sa.Column('version', sa.String(), nullable=False),
    sa.Column('fix_version', sa.String(), nullable=True),
    sa.Column('prioritized', sa.Boolean(), nullable=True),
    sa.Column('vendor_confirmed', sa.Boolean(), nullable=True),
    sa.Column('has_poc', sa.Boolean(), nullable=True),
    sa.Column('has_exploit', sa.Boolean(), nullable=True),
    sa.Column('direct', sa.Boolean(), nullable=True),
    sa.Column('indirect', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['analysis_id'], ['Analysis.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('VulnerableDependencyReference',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(), nullable=True),
    sa.Column('url', sa.String(), nullable=True),
    sa.Column('vulnerable_dependency_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['vulnerable_dependency_id'], ['VulnerableDependency.id'], ),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    op.drop_table('VulnerableDependencyReference')
    op.drop_table('VulnerableDependency')
