#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 18-6-19 下午6:08
# @Author  : Skye
# @Site    : 
# @File    : model.py
# @Software: PyCharm
from sqlalchemy import BOOLEAN
from sqlalchemy.orm import relationship

from src.app.main import db


class User(db.Model):
    """
    用户表
    """
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(80), nullable=True)
    lastName = db.Column(db.String(80), nullable=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    checkCode = db.Column(db.String(4), nullable=True)
    password = db.Column(db.String(256), nullable=True)
    defaultGroupId = db.Column(db.Integer, nullable=True)
    avatar = db.Column(db.String(256), nullable=True)
    sessionToken = db.Column(db.String(256), nullable=True)
    isDisable = db.Column(db.SmallInteger, default=0, nullable=False)
    createdAt = db.Column(db.DateTime, nullable=True)
    updatedAt = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return '<User %r>' % self.username


class Group(db.Model):
    """
    分组表
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    avatar = db.Column(db.String(256), nullable=True)
    desc = db.Column(db.String(256), nullable=False)
    belongUserId = db.Column(db.Integer, nullable=True)
    isPublic = db.Column(db.SmallInteger, default=0, nullable=False)
    checkCode = db.Column(db.String(4), nullable=True)
    isDisable = db.Column(db.SmallInteger, default=0, nullable=False)
    createdAt = db.Column(db.DateTime, nullable=True)
    updatedAt = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return '<Group %r>' % self.name


class GroupUser(db.Model):
    """
    用户分组关联表
    """
    id = db.Column(db.Integer, primary_key=True)
    userId = db.Column(db.Integer, nullable=False)
    groupId = db.Column(db.Integer, nullable=False)
    isDisable = db.Column(db.SmallInteger, default=0, nullable=False)
    isAudit = db.Column(db.SmallInteger, default=0, nullable=False)
    createdAt = db.Column(db.DateTime, nullable=True)
    updatedAt = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return '<GroupUser %r>' % self.id


class Space(db.Model):
    """
    空间表
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    avatar = db.Column(db.String(256), nullable=True)
    belongUserId = db.Column(db.Integer, nullable=True)
    belongGroupId = db.Column(db.Integer, nullable=True)
    isPublic = db.Column(db.SmallInteger, default=0, nullable=False)
    isDisable = db.Column(db.SmallInteger, default=0, nullable=False)
    createdAt = db.Column(db.DateTime, nullable=True)
    updatedAt = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return '<Space %r>' % self.name


class Position(db.Model):
    """
    位置表
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    avatar = db.Column(db.String(256), nullable=True)
    belongUserId = db.Column(db.Integer, nullable=True)
    belongGroupId = db.Column(db.Integer, nullable=True)
    spaceId = db.Column(db.Integer, nullable=True)
    isPublic = db.Column(db.SmallInteger, default=0, nullable=False)
    coordinate = db.Column(db.String(256), nullable=True)
    isDisable = db.Column(db.SmallInteger, default=0, nullable=False)
    createdAt = db.Column(db.DateTime, nullable=True)
    updatedAt = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return '<Group %r>' % self.name


class Goods(db.Model):
    """
    物品表
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    avatar = db.Column(db.String(256), nullable=True)
    belongUserId = db.Column(db.Integer, nullable=True)
    belongGroupId = db.Column(db.Integer, nullable=True)
    spaceId = db.Column(db.Integer, nullable=True)
    positionId = db.Column(db.Integer, nullable=True)
    type = db.Column(db.SmallInteger, default=0, nullable=False)
    isPublic = db.Column(db.SmallInteger, default=0, nullable=False)
    coordinate = db.Column(db.String(256), nullable=True)
    isDisable = db.Column(db.SmallInteger, default=0, nullable=False)
    createdAt = db.Column(db.DateTime, nullable=True)
    updatedAt = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return '<Goods %r>' % self.name


class Notes(db.Model):
    """
    备注表
    """
    id = db.Column(db.Integer, primary_key=True)
    note = db.Column(db.String(1024), nullable=True)
    belongUserId = db.Column(db.Integer, nullable=True)
    belongGroupId = db.Column(db.Integer, nullable=True)
    spaceId = db.Column(db.Integer, nullable=True)
    positionId = db.Column(db.Integer, nullable=True)
    goodsId = db.Column(db.Integer, nullable=True)
    isPublic = db.Column(db.SmallInteger, default=0, nullable=False)
    isDisable = db.Column(db.SmallInteger, default=0, nullable=False)
    createdAt = db.Column(db.DateTime, nullable=True)
    updatedAt = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return '<Notes %r>' % self.id


class Marks(db.Model):
    """
    标记表
    """
    id = db.Column(db.Integer, primary_key=True)
    belongUserId = db.Column(db.Integer, nullable=True)
    belongGroupId = db.Column(db.Integer, nullable=True)
    spaceId = db.Column(db.Integer, nullable=True)
    positionId = db.Column(db.Integer, nullable=True)
    goodsId = db.Column(db.Integer, nullable=True)
    isPublic = db.Column(db.SmallInteger, default=0, nullable=False)
    isDisable = db.Column(db.SmallInteger, default=0, nullable=False)
    createdAt = db.Column(db.DateTime, nullable=True)
    updatedAt = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return '<Marks %r>' % self.id


class News(db.Model):
    """
    动态表
    """
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    content = db.Column(db.String(1024), nullable=False)
    type = db.Column(db.Integer, nullable=False)
    belongUserId = db.Column(db.Integer, nullable=True)
    belongGroupId = db.Column(db.Integer, nullable=True)
    spaceId = db.Column(db.Integer, nullable=True)
    positionId = db.Column(db.Integer, nullable=True)
    avatar = db.Column(db.String(80), nullable=False)
    goodsId = db.Column(db.Integer, nullable=True)
    isPublic = db.Column(db.SmallInteger, default=0, nullable=False)
    isDisable = db.Column(db.SmallInteger, default=0, nullable=False)
    createdAt = db.Column(db.DateTime, nullable=True)
    updatedAt = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return '<News %r>' % self.id


class Reads(db.Model):
    """
    已读表
    """
    id = db.Column(db.Integer, primary_key=True)
    newsId = db.Column(db.Integer, nullable=True)
    belongUserId = db.Column(db.Integer, nullable=True)
    createdAt = db.Column(db.DateTime, nullable=True)
    updatedAt = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return '<News %r>' % self.id
