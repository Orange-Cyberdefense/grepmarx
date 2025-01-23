"""Additionnal insights for VulnerableDependency

Revision ID: 5655f7c23045
Revises: 3965ec26d479
Create Date: 2024-04-18 11:36:00.667561

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5655f7c23045'
down_revision = '3965ec26d479'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('VulnerableDependency', schema=None) as batch_op:
        batch_op.add_column(sa.Column('distro_specific', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('direct_dep', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('known_exploit', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('exploitable', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('flagged_weakness', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('suppress_for_containers', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('uninstall_candidate', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('indirect_dependency', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('local_install', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('reachable_Bounty_target', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('bug_Bounty_target', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('has_PoC', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('reachable', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('vendor_Confirmed', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('reachable_and_Exploitable', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('known_Exploits', sa.Boolean(), nullable=True))



def downgrade():
    with op.batch_alter_table('VulnerableDependency', schema=None) as batch_op:
        batch_op.drop_column('known_Exploits')
        batch_op.drop_column('reachable_and_Exploitable')
        batch_op.drop_column('vendor_Confirmed')
        batch_op.drop_column('reachable')
        batch_op.drop_column('has_PoC')
        batch_op.drop_column('bug_Bounty_target')
        batch_op.drop_column('reachable_Bounty_target')
        batch_op.drop_column('local_install')
        batch_op.drop_column('indirect_dependency')
        batch_op.drop_column('uninstall_candidate')
        batch_op.drop_column('suppress_for_containers')
        batch_op.drop_column('flagged_weakness')
        batch_op.drop_column('exploitable')
        batch_op.drop_column('known_exploit')
        batch_op.drop_column('direct_dep')
        batch_op.drop_column('distro_specific')

