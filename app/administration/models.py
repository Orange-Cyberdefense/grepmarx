# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""
from app import db
from sqlalchemy import Column, Integer, String


class LdapConf(db.Model):

    __tablename__ = "LdapConf"

    id = Column(Integer, primary_key=True)
    title = Column(String, nullable=False)
    url = Column(String, nullable=False)
    bind_Dnd = Column(String, nullable=False)
    search_base = Column(String, nullable=False)
    search_filter = Column(String)



