"""empty message

Revision ID: 6deaad4064b8
Revises: 16d5fffffaca
Create Date: 2023-01-19 11:47:59.759088

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import Integer, String
from sqlalchemy.sql import column, table

# revision identifiers, used by Alembic.
revision = '6deaad4064b8'
down_revision = '16d5fffffaca'
branch_labels = None
depends_on = None


def upgrade():

    supported_language = table(
        "SupportedLanguage",
        column("id", Integer),
        column("name", String),
        column("extensions", String),
    )

    op.bulk_insert(
        supported_language,
        [
            {"id": 18, "name": "Swift", "extensions": ".swift,.SWIFT"},
        ],
    )


def downgrade():
    pass
