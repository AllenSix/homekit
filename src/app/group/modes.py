#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 18-6-27 下午12:13
# @Author  : Skye
# @Site    : 
# @File    : modes.py
# @Software: PyCharm
from sqlalchemy import func, desc, or_, and_

from src.app.main import db
from src.app.models.model import Position, Goods, Marks, News, Notes


def get_position_num_in_space(space_id=-1, user_default_group_id=-1, user_id=-1):
    return db.session.query(Position).filter(Position.spaceId == space_id, Position.isDisable == 0).filter(
        or_(
            and_(
                Position.isPublic == 1,
                Position.isDisable == 0,
                Position.belongGroupId == user_default_group_id
            ),
            and_(
                Position.isPublic == 0,
                Position.belongUserId == user_id
            )
        )
    ).with_entities(func.count(Position.id)).scalar()


def get_goods_num_in_space(space_id=-1, user_default_group_id=-1, user_id=-1):
    return db.session.query(Goods).filter(Goods.spaceId == space_id, Goods.isDisable == 0).filter(
        or_(
            and_(
                Goods.isPublic == 1,
                Goods.isDisable == 0,
                Goods.belongGroupId == user_default_group_id
            ),
            and_(
                Goods.isPublic == 0,
                Goods.belongUserId == user_id
            )
        )
    ).with_entities(func.count(Goods.id)).scalar()


def get_members_num_in_space(space_id=-1):
    user_id_set = set()
    space_user_ids = db.session.query(Position.belongUserId).filter(Position.spaceId == space_id).distinct().all()
    for user_id in space_user_ids:
        user_id_set.add(user_id)
    goods_user_ids = db.session.query(Goods.belongUserId).filter(Goods.spaceId == space_id).distinct().all()
    for user_id in goods_user_ids:
        user_id_set.add(user_id)
    return len(user_id_set)


def get_goods_num_in_position(position_id=-1, user_default_group_id=-1, user_id=-1):
    return db.session.query(Goods).filter(Goods.positionId == position_id, Goods.isDisable == 0).filter(
        or_(
            and_(
                Goods.isPublic == 1,
                Goods.isDisable == 0,
                Goods.belongGroupId == user_default_group_id
            ),
            and_(
                Goods.isPublic == 0,
                Goods.belongUserId == user_id
            )
        )
    ).with_entities(func.count(Goods.id)).scalar()


def get_members_num_in_position(position_id=-1):
    user_id_set = set()
    goods_user_ids = db.session.query(Goods.belongUserId).filter(Goods.positionId == position_id).distinct().all()
    for user_id in goods_user_ids:
        user_id_set.add(user_id)
    return len(user_id_set)


def get_marks_num_in_goods(goods_id=-1):
    user_id_set = set()
    goods_user_ids = db.session.query(Marks.belongUserId).filter(Marks.goodsId == goods_id).distinct().all()
    for user_id in goods_user_ids:
        user_id_set.add(user_id)
    return len(user_id_set)


def get_news_num_in_goods(goods_id=-1):
    return db.session.query(News).filter(News.goodsId == goods_id).filter(
        News.isDisable == 0).with_entities(func.count(News.id)).scalar()


def get_latest_note_in_goods(goods_id=-1):
    notes = db.session.query(Notes.note).filter(Notes.goodsId == goods_id).order_by(desc(Notes.id)).first()
    if notes:
        return notes.note
    else:
        return ""
