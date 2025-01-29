"""Add support for HCL

Revision ID: 9acfb9d8825a
Revises: 5c6ab735e82f
Create Date: 2025-01-23 14:21:23.637617

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '9acfb9d8825a'
down_revision = '5c6ab735e82f'
branch_labels = None
depends_on = None

def upgrade():
    op.execute("INSERT INTO \"SupportedLanguage\" (name, extensions) VALUES ('HCL', '.hcl,.tf,.tfvars,.nomad,.vcl')")


def downgrade():
    op.execute("DELETE FROM \"SupportedLanguage\" WHERE name='HCL'")
