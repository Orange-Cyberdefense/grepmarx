"""Add support for HCL

Revision ID: 9acfb9d8825a
Revises: 5c6ab735e82f
Create Date: 2025-01-23 14:21:23.637617

"""
from app import db
from app.rules.models import SupportedLanguage


# revision identifiers, used by Alembic.
revision = '9acfb9d8825a'
down_revision = '5c6ab735e82f'
branch_labels = None
depends_on = None


def upgrade():
    db.session.add(
        SupportedLanguage(
            name="HCL",
            extensions=".hcl,.tf,.tfvars,.nomad,.vcl",
        )
    )
    db.session.commit()


def downgrade():
    SupportedLanguage.query.filter_by(name="HCL").delete()
    db.session.commit()