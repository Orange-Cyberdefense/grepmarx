"""Add support for Yaml

Revision ID: 5c6ab735e82f
Revises: f3c49be13e32
Create Date: 2025-01-22 14:02:48.678500

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5c6ab735e82f'
down_revision = 'f3c49be13e32'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("INSERT INTO SupportedLanguage (name, extensions) VALUES ('Yaml', '.yml,.yaml')")


def downgrade():
    op.execute("DELETE FROM SupportedLanguage WHERE name='Yaml'")
