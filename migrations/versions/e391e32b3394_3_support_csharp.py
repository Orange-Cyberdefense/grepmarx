"""3 SUPPORT CSHARP

Revision ID: e391e32b3394
Revises: 51b79bdb33b2
Create Date: 2023-02-19 14:13:54.745031

"""
from alembic import op
import sqlalchemy as sa

from app import db
from app.rules.models import SupportedLanguage

# revision identifiers, used by Alembic.
revision = "e391e32b3394"
down_revision = "51b79bdb33b2"
branch_labels = None
depends_on = None


def upgrade():
    db.session.add(
        SupportedLanguage(
            name="C#",
            extensions=".cs,.cshtml,.xaml,.vb,.config,.aspx,.ascx,.asax,.tag,.master,.xml",
        )
    )
    db.session.commit()


def downgrade():
    SupportedLanguage.query.filter_by(name="C#").delete()
    db.session.commit()
