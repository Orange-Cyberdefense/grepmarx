# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import os
from datetime import datetime
from shutil import rmtree

import git
from grepmarx import db
from grepmarx.constants import RULES_PATH
from sqlalchemy import Column, DateTime, Integer, String


class RuleRepository(db.Model):

    __tablename__ = "RuleRepository"

    id = Column("id", Integer, primary_key=True)
    name = Column(String, unique=True)
    description = Column(String)
    uri = Column(String)
    last_update_on = Column(DateTime())

    def clone(self):
        repo_path = os.path.join(RULES_PATH, self.name)
        git.Repo.clone_from(self.uri, repo_path)
        self.last_update_on = datetime.now()
        db.session.commit()

    def pull(self):
        repo_path = os.path.join(RULES_PATH, self.name)
        git.cmd.Git(repo_path).pull()
        self.last_update_on = datetime.now()
        db.session.commit()

    def remove(self):
        # Remove repository folder on disk
        repo_path = os.path.join(RULES_PATH, self.name)
        if os.path.isdir(repo_path):
            rmtree(repo_path)
        db.session.delete(self)
        db.session.commit()
