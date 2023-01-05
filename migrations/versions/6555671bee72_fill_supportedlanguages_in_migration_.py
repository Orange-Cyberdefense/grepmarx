"""Fill SupportedLanguages in migration scripts

Revision ID: 6555671bee72
Revises: e4159237369c
Create Date: 2023-01-04 21:37:01.597661

"""
from alembic import op
from sqlalchemy.sql import table, column
from sqlalchemy import String, Integer
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6555671bee72'
down_revision = 'e4159237369c'
branch_labels = None
depends_on = None


def upgrade():
    # SupportedLanguage.query.delete()
    # db.session.commit()

    op.execute('TRUNCATE "SupportedLanguage" CASCADE')

    supported_language = table(
        "SupportedLanguage",
        column("id", Integer),
        column("name", String),
        column("extensions", String),
    )

    op.bulk_insert(
        supported_language,
        [
            {"id": 1, "name": "Python", "extensions": "py,pyc,pyd,pyo,pyw,pyz,pyi"},
            {
                "id": 2,
                "name": "C",
                "extensions": ".cpp,.c++,.cxx,.hpp,.hh,.h++,.hxx,.c,.cc,.h",
            },
            {"id": 3, "name": "JavaScript", "extensions": ".js,.htm,.html"},
            {"id": 4, "name": "TypeScript", "extensions": ".ts,.html"},
            {"id": 5, "name": "JSON", "extensions": ".json"},
            {
                "id": 6,
                "name": "PHP",
                "extensions": ".php,.php3,.php4,.php5,.php5.6,.phtm,.phtml,.tpl,.ctp,.twig",
            },
            {
                "id": 7,
                "name": "Java",
                "extensions": ".javasln,.project,.java,.jsp,.jspf,.tag,.tld,.hbs,.properties",
            },
            {"id": 8, "name": "Go", "extensions": ".go"},
            {"id": 9, "name": "OCaml", "extensions": ".ml,.mli"},
            {"id": 10, "name": "Ruby", "extensions": ".rb,.rhtml,.rxml,.rjs,.erb"},
            {"id": 11, "name": "Kotlin", "extensions": ".kt,.kts"},
            {"id": 12, "name": "Bash", "extensions": ".sh,.bash"},
            {"id": 13, "name": "Rust", "extensions": ".rs,.rlib"},
            {"id": 14, "name": "Scala", "extensions": ".scala,.sc"},
            {"id": 15, "name": "Solidity", "extensions": ".sol"},
            {"id": 16, "name": "Terraform", "extensions": ".tf"},
            {"id": 17, "name": "Generic", "extensions": ""},
        ],
    )

def downgrade():
        print("")