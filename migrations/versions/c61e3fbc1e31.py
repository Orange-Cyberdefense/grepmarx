"""Add support for html, apex, dockerfile, clojure, dart, elixir, regex

Revision ID: c61e3fbc1e31
Revises: 6f598e9117c6
Create Date: 2025-01-23 17:52:00.999890

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c61e3fbc1e31'
down_revision = '6f598e9117c6'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("INSERT INTO \"SupportedLanguage\" (name, extensions) VALUES ('HTML', '.html,.htm,.xhtml')")
    op.execute("INSERT INTO \"SupportedLanguage\" (name, extensions) VALUES ('Apex', '.cls,.trigger')")
    op.execute("INSERT INTO \"SupportedLanguage\" (name, extensions) VALUES ('Dockerfile', 'Dockerfile,.dockerfile')")
    op.execute("INSERT INTO \"SupportedLanguage\" (name, extensions) VALUES ('Clojure', '.clj,.cljs,.cljc,.edn')")
    op.execute("INSERT INTO \"SupportedLanguage\" (name, extensions) VALUES ('Dart', '.dart,.dart.js')")
    op.execute("INSERT INTO \"SupportedLanguage\" (name, extensions) VALUES ('Elixir', '.ex,.exs,.eex,.leex')")
    op.execute("INSERT INTO \"SupportedLanguage\" (name, extensions) VALUES ('Regex', '')")
    op.execute("UPDATE \"SupportedLanguage\" SET shortname = 'csharp' WHERE name = 'C#'")

def downgrade():
    op.execute("DELETE FROM \"SupportedLanguage\" WHERE name='HTML'")
    op.execute("DELETE FROM \"SupportedLanguage\" WHERE name='Apex'")
    op.execute("DELETE FROM \"SupportedLanguage\" WHERE name='Dockerfile'")
    op.execute("DELETE FROM \"SupportedLanguage\" WHERE name='Clojure'")
    op.execute("DELETE FROM \"SupportedLanguage\" WHERE name='Dart'")
    op.execute("DELETE FROM \"SupportedLanguage\" WHERE name='Elixir'")
    op.execute("DELETE FROM \"SupportedLanguage\" WHERE name='Regex'")
