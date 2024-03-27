"""fix team class test in database

Revision ID: 0914a29d984d
Revises: 6201ea3d70cc
Create Date: 2024-02-28 11:39:50.129629

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0914a29d984d'
down_revision = '6201ea3d70cc'
branch_labels = None
depends_on = None


def upgrade():
    # Ajouter la colonne team_id à la table Project
    with op.batch_alter_table('Project', schema=None) as batch_op:
        batch_op.add_column(sa.Column('team_id', sa.Integer(), nullable=True))

    # Créer la contrainte étrangère avec un nom spécifié
    with op.batch_alter_table('Project', schema=None) as batch_op:
        batch_op.create_foreign_key('fk_project_team_id', 'Team', ['team_id'], ['id'])

    # Supprimer la colonne autorisations de la table Team
    with op.batch_alter_table('Team', schema=None) as batch_op:
        batch_op.drop_column('autorisations')


def downgrade():
    # Ajouter la colonne autorisations à la table Team
    with op.batch_alter_table('Team', schema=None) as batch_op:
        batch_op.add_column(sa.Column('autorisations', sa.VARCHAR(), nullable=True))

    # Supprimer la contrainte étrangère de la table Project
    with op.batch_alter_table('Project', schema=None) as batch_op:
        batch_op.drop_constraint('fk_project_team_id', type_='foreignkey')

    # Supprimer la colonne team_id de la table Project
    with op.batch_alter_table('Project', schema=None) as batch_op:
        batch_op.drop_column('team_id')

