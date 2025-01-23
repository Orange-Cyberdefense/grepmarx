"""Add shortname to SupportedLanguage

Revision ID: 6f598e9117c6
Revises: 9acfb9d8825a
Create Date: 2025-01-23 16:19:43.826502

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '6f598e9117c6'
down_revision = '9acfb9d8825a'
branch_labels = None
depends_on = None


def upgrade():
    # Add 'shortname' column
    with op.batch_alter_table('SupportedLanguage', schema=None) as batch_op:
        batch_op.add_column(sa.Column('shortname', sa.String(), nullable=True))
        batch_op.create_unique_constraint("unique_shortname", ['shortname'])

    # Fill it for JS, TS and KT 
    op.execute("UPDATE SupportedLanguage SET shortname = 'js' WHERE name = 'JavaScript'")
    op.execute("UPDATE SupportedLanguage SET shortname = 'ts' WHERE name = 'TypeScript'")
    op.execute("UPDATE SupportedLanguage SET shortname = 'kt' WHERE name = 'Kotlin'")
    op.execute("UPDATE SupportedLanguage SET shortname = 'yml' WHERE name = 'Yaml'")


def downgrade():
    with op.batch_alter_table('SupportedLanguage', schema=None) as batch_op:
        batch_op.drop_constraint("unique_shortname", type_='unique')
        batch_op.drop_column('shortname')
