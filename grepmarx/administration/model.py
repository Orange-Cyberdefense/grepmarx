# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import os
import git
from grepmarx.rules import model
from grepmarx import db
from sqlalchemy import Column, Integer, String, DateTime
from shutil import rmtree

class RuleRepository(db.Model):

    __tablename__ = "RuleRepository"

    id = Column("id", Integer, primary_key=True)
    name = Column(String, unique=True)
    description = Column(String)
    uri = Column(String)
    last_update_on = Column(DateTime())

    def clone(self):
        repo_path = os.path.join(model.Rule.RULES_PATH, self.name)
        git.Repo.clone_from(self.uri, repo_path)

    def remove(self):
        # Remove repository folder on disk
        repo_path = os.path.join(model.Rule.RULES_PATH, self.name)
        if os.path.isdir(repo_path):
            rmtree(repo_path)
        db.session.delete(self)
        db.session.commit()
