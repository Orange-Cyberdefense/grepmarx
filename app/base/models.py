# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
Copyright (c) 2021 - present Orange Cyberdefense
"""

from flask_login import UserMixin
from sqlalchemy import Boolean, Column, Integer, LargeBinary, String, Table, ForeignKey
from sqlalchemy.orm import relationship

from app import db, login_manager
from app.base.util import hash_pass
from app.constants import AUTH_LOCAL, ROLE_USER
from app.projects.models import Project

team_members_association = Table(
    'team_members', db.metadata,
    Column('team_id', Integer, ForeignKey('Team.id', name='fk_team_members_team_id')),
    Column('user_id', Integer, ForeignKey('User.id', name='fk_team_members_user_id'))
)

team_projet_association = Table(
    'team_projets', db.metadata,
    Column('team_id', Integer, ForeignKey('Team.id', name='fk_team_projets_team_id')),
    Column('project_id', Integer, ForeignKey('Project.id', name='fk_team_projets_project_id'))
)

class User(db.Model, UserMixin):

    __tablename__ = "User"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    first_name = Column(String)
    last_name = Column(String)
    role = Column(String, default=ROLE_USER)
    local = Column(Boolean, default=AUTH_LOCAL)
    email = Column(String, unique=True)
    password = Column(LargeBinary)
    dark_theme = Column(Boolean, default=False)

    def __init__(self, **kwargs):
        for property, value in kwargs.items():
            # depending on whether value is an iterable or not, we must
            # unpack it's value (when **kwargs is request.form, some values
            # will be a 1-element list)
            if hasattr(value, "__iter__") and not isinstance(value, str):
                # the ,= unpack of a singleton fails PEP8 (travis flake8 test)
                value = value[0]

            if property == "password":
                value = hash_pass(value)  # we need bytes here (not plain str)

            setattr(self, property, value)

    def __repr__(self):
        return f"<User(username={self.username})>"


class Team(db.Model):

    __tablename__ = "Team"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    creator = Column(String)
    user_id = db.Column(Integer, db.ForeignKey('User.id'))
    members = db.relationship("User", secondary=team_members_association, backref="team_members")
    projects = db.relationship("Project", secondary=team_projet_association, backref="projets")


@login_manager.user_loader
def user_loader(id):
    return User.query.filter_by(id=id).first()


@login_manager.request_loader
def request_loader(request):
    username = request.form.get("username")
    user = User.query.filter_by(username=username).first()
    return user if user else None