#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 18-6-20 上午10:32
# @Author  : Skye
# @Site    : 
# @File    : views.py
# @Software: PyCharm

from flask import jsonify
from sqlalchemy import exists, not_, and_, desc, or_

from src.app.group.modes import *
from src.app.main import db
from src.app.models.model import User, Space, Position, Group, Goods, Notes, Marks, News, Reads
from src.app.util import util
from src.app.util.mail import APP_SECRET


def create_space(session_token, name, is_public, avatar, group_id):
    """
    创建组，并创建一条关联记录
    todo check user belong group
    :param group_id:
    :param avatar:
    :param is_public:
    :param name:
    :param session_token:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss userk'}}), 200
    space = Space(name=name, avatar=avatar, belongGroupId=group_id, belongUserId=user_id, isPublic=is_public)
    space.createdAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    space.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.add(space)
    db.session.commit()
    return jsonify({"objectId": str(space.id)})


def query_space(session_token, skip, limit, params):
    """
    查询有权限对组，
    :param params:
    :param limit:
    :param skip:
    :param session_token:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss userk'}}), 200
    query = db.session.query(Space, User).filter(Space.belongUserId == User.id).filter(
        Space.belongGroupId == user.defaultGroupId) \
        .filter(Space.isDisable == 0)
    if params is None:
        params = {}
    if "belongGroupId" in params:
        query = query.filter(Space.belongGroupId == params["belongGroupId"])
    if "objectId" in params:
        query = query.filter(Space.id == params["objectId"])
    # 私密性
    query = query.filter(or_(
        Space.isPublic == 1, and_(
            Space.isPublic == 0,
            Space.belongUserId == user_id)
    ))

    query = query.limit(limit).offset(skip).all()
    results = []
    for data, user in query:
        results.append({"objectId": data.id,
                        "name": data.name,
                        "avatar": data.avatar,
                        "belongUserId": data.belongUserId,
                        "belongUserName": user.lastName,
                        "belongGroupId": data.belongGroupId,
                        "positionNum": get_position_num_in_space(data.id),
                        "goodsNum": get_goods_num_in_space(data.id),
                        "membersNum": get_members_num_in_space(data.id),
                        "isPublic": data.isPublic,
                        "createdAt": util.get_iso8601_from_dt(data.createdAt),
                        "updatedAt": util.get_iso8601_from_dt(data.updatedAt), })
    return jsonify({"results": results})


def update_space(session_token, todo_id, name, is_public, avatar, is_disable):
    """
    更新一条项目记录
    todo check user belong group
    :param is_disable:
    :param session_token:
    :param todo_id:
    :param name:
    :param is_public:
    :param avatar:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss user'}}), 200
    space = Space.query.filter_by(id=todo_id, belongUserId=user_id).first()
    if space is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss space'}}), 200
    if name != "":
        space.name = name
    if is_public is not None:
        space.isPublic = is_public
    if avatar != "":
        space.avatar = avatar
    if is_disable is not None:
        space.isDisable = is_disable
    space.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.commit()
    return jsonify({"result": {"data": {}, "error_code": 0, "msg": "空间修改成功"}})


def create_position(session_token, name, is_public, avatar, space_id, coordinate):
    """
    创建组，并创建一条关联记录
    :param desc:
    :param avatar:
    :param is_public:
    :param name:
    :param session_token:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss userk'}}), 200
    space = Space.query.filter_by(id=space_id).first()
    if space is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss space'}}), 200
    position = Position(name=name, avatar=avatar, coordinate=coordinate, belongUserId=user_id,
                        belongGroupId=space.belongGroupId, isPublic=is_public, spaceId=space_id)
    position.createdAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    position.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.add(position)
    db.session.commit()
    save_news(user, title="", content="", type=4, space_id=position.spaceId, position_id=position.id,
              goods_id=-1)
    return jsonify({"objectId": str(position.id)})


def query_position(session_token, skip, limit, params):
    """
    查询有权限对组，
    :param params:
    :param limit:
    :param skip:
    :param session_token:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss user'}}), 200
    query = db.session.query(Position, User, Space) \
        .filter(Position.spaceId == Space.id).filter(Position.belongUserId == User.id)
    if params is None:
        params = {}
    if "belongGroupId" in params:
        query = query.filter(Position.belongGroupId == params["belongGroupId"])
    if "spaceId" in params:
        query = query.filter(Position.spaceId == params["spaceId"])
    if "objectId" in params:
        query = query.filter(Position.id == params["objectId"])
    # 私密性
    query = query.filter(or_(
        Position.isPublic == 1, and_(
            Position.isPublic == 0,
            Position.belongUserId == user_id)
    ))
    query = query.filter(Position.isDisable == 0).limit(limit).offset(skip).all()
    results = []
    for data, user, space in query:
        results.append({"objectId": data.id,
                        "name": data.name,
                        "avatar": data.avatar,
                        "coordinate": data.coordinate,
                        "belongUserId": data.belongUserId,
                        "belongGroupId": data.belongGroupId,
                        "spaceId": data.spaceId,
                        "belongUserName": user.lastName,
                        "spaceName": space.name,
                        "goodsNum": get_goods_num_in_position(data.spaceId),
                        "membersNum": get_members_num_in_position(data.spaceId),
                        "isPublic": data.isPublic,
                        "createdAt": util.get_iso8601_from_dt(data.createdAt),
                        "updatedAt": util.get_iso8601_from_dt(data.updatedAt), })
    return jsonify({"results": results})


def update_position(session_token, todo_id, name, is_public, avatar, coordinate, is_disable):
    """
    更新一条项目记录
    :param is_disable:
    :param session_token:
    :param todo_id:
    :param name:
    :param is_public:
    :param avatar:
    :param coordinate:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss user'}}), 200
    position = Position.query.filter_by(id=todo_id, belongUserId=user_id).first()
    if position is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss position'}}), 200
    if name != "":
        position.name = name
    if is_public is not None:
        position.isPublic = is_public
    if avatar != "":
        position.avatar = avatar
    if coordinate != "":
        position.coordinate = coordinate
    if is_disable is not None:
        position.isDisable = is_disable
    position.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.commit()
    return jsonify({"result": {"data": {}, "error_code": 0, "msg": "项目修改成功"}})


def create_goods(session_token, name, is_public, avatar, coordinate, position_id, type, internal_id=""):
    """
    创建组，并创建一条关联记录
    :param internal_id:
    :param type:
    :param position_id:
    :param coordinate:
    :param avatar:
    :param is_public:
    :param name:
    :param session_token:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss userk'}}), 200
    position = Position.query.filter_by(id=position_id).first()
    if position is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss position'}}), 200
    goods = Goods(name=name, avatar=avatar, coordinate=coordinate, belongUserId=user_id,
                  belongGroupId=position.belongGroupId, isPublic=is_public, spaceId=position.spaceId,
                  positionId=position_id, type=type)
    goods.createdAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    goods.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.add(goods)
    db.session.commit()
    save_news(user, title="", content="", type=1, space_id=goods.spaceId, position_id=goods.positionId,
              goods_id=goods.id)
    return jsonify({"objectId": str(goods.id), "__internalId": internal_id})


def query_goods(session_token, skip, limit, params):
    """
    查询有权限对组， TODO 关联查询
    :param params:
    :param limit:
    :param skip:
    :param session_token:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss user'}}), 200
    query = db.session.query(Goods, Space, User, Position).filter(Goods.spaceId == Space.id) \
        .filter(Goods.belongUserId == User.id) \
        .filter(Goods.positionId == Position.id)
    if params is None:
        params = {}
    if "belongGroupId" in params:
        query = query.filter(Goods.belongGroupId == params["belongGroupId"])
    if "spaceId" in params:
        query = query.filter(Goods.spaceId == params["spaceId"])
    if "positionId" in params:
        query = query.filter(Goods.positionId == params["positionId"])
    if "type" in params:
        query = query.filter(Goods.type == params["type"])
    if "objectId" in params:
        query = query.filter(Goods.id == params["objectId"])
    if "isDisable" in params:
        query = query.filter(Goods.isDisable == params["isDisable"])
    else:
        query = query.filter(Goods.isDisable == 0)
    # 私密性
    query = query.filter(or_(
        Goods.isPublic == 1, and_(
            Goods.isPublic == 0,
            Goods.belongUserId == user_id)
    ))
    query = query.order_by(desc(Goods.id)).limit(limit).offset(skip).all()
    results = []
    for data, space, user, position in query:
        results.append({"objectId": data.id,
                        "name": data.name,
                        "avatar": data.avatar,
                        "coordinate": data.coordinate,
                        "belongUserId": data.belongUserId,
                        "belongUserName": user.lastName + user.firstName,
                        "belongGroupId": data.belongGroupId,
                        "spaceId": data.spaceId,
                        "spaceName": space.name,
                        "positionId": data.positionId,
                        "positionName": position.name,
                        "type": data.type,
                        "isPublic": data.isPublic,
                        "note": get_latest_note_in_goods(data.id),
                        "marksNum": get_marks_num_in_goods(data.id),
                        "newsNum": get_news_num_in_goods(data.id),
                        "createdAt": util.get_iso8601_from_dt(data.createdAt),
                        "updatedAt": util.get_iso8601_from_dt(data.updatedAt), })
    return jsonify({"results": results})


def update_goods(session_token, todo_id, name, is_public, avatar, desc, is_disable, coordinate):
    """
    更新一条项目记录
    :param session_token:
    :param todo_id:
    :param name:
    :param is_public:
    :param avatar:
    :param desc:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss user'}}), 200
    goods = Goods.query.filter_by(id=todo_id).first()
    if goods is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss goods'}}), 200
    if name != "":
        goods.name = name
    if is_public is not None:
        goods.isPublic = is_public
    if desc != "":
        goods.desc = desc
    if avatar != "":
        goods.avatar = avatar
    if coordinate != "":
        goods.coordinate = coordinate
    if is_disable is not None:
        goods.isDisable = is_disable
    goods.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.commit()
    return jsonify({"result": {"data": {}, "error_code": 0, "msg": "项目修改成功"}})


def create_notes(session_token, note, is_public, goods_id):
    """
    创建组，并创建一条关联记录
    :param goods_id:
    :param note:
    :param is_public:
    :param session_token:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss userk'}}), 200
    goods = Goods.query.filter_by(id=goods_id).first()
    if goods is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss position'}}), 200
    notes = Notes(note=note, belongUserId=user_id, belongGroupId=user.defaultGroupId, spaceId=goods.spaceId,
                  positionId=goods.positionId, goodsId=goods_id, isPublic=is_public)
    notes.createdAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    notes.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.add(notes)
    db.session.commit()
    save_news(user, title="", content=note, type=3, space_id=goods.spaceId, position_id=goods.positionId,
              goods_id=goods_id)
    return jsonify({"objectId": str(notes.id)})


def query_notes(session_token, skip, limit, params):
    """
    查询有权限对组，
    :param params:
    :param limit:
    :param skip:
    :param session_token:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss user'}}), 200
    query = db.session.query(Notes).filter(Notes.isDisable == 0)
    if params is None:
        params = {}
    if "belongGroupId" in params:
        query = query.filter(Notes.belongGroupId == params["belongGroupId"])
    if "spaceId" in params:
        query = query.filter(Notes.spaceId == params["spaceId"])
    if "positionId" in params:
        query = query.filter(Notes.positionId == params["positionId"])
    if "goodsId" in params:
        query = query.filter(Notes.goodsId == params["goodsId"])
    if "objectId" in params:
        query = query.filter(Notes.id == params["objectId"])
    query = query.order_by(desc(Notes.id)).limit(limit).offset(skip).all()
    results = []
    for data in query:
        results.append({"objectId": data.id,
                        "note": data.note,
                        "belongUserId": data.belongUserId,
                        "belongGroupId": data.belongGroupId,
                        "spaceId": data.spaceId,
                        "positionId": data.positionId,
                        "goodsId": data.goodsId,
                        "isPublic": data.isPublic,
                        "createdAt": util.get_iso8601_from_dt(data.createdAt),
                        "updatedAt": util.get_iso8601_from_dt(data.updatedAt), })
    return jsonify({"results": results})


def update_notes(session_token, todo_id, note, is_public, is_disable):
    """
    更新一条项目记录
    :param is_disable:
    :param session_token:
    :param todo_id:
    :param is_public:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss user'}}), 200
    obj = Notes.query.filter_by(id=todo_id, belongUserId=user_id).first()
    if obj is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss group'}}), 200
    if note != "":
        obj.note = note
    if is_public is not None:
        obj.isPublic = is_public
    if is_disable is not None:
        obj.isDisable = is_disable
    obj.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.commit()

    return jsonify({"result": {"data": {}, "error_code": 0, "msg": "项目修改成功"}})


def create_marks(session_token, is_public, position_id, goods_id):
    """
    创建组，并创建一条关联记录
    :param position_id:
    :param goods_id:
    :param is_public:
    :param session_token:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss userk'}}), 200
    position = Position.query.filter_by(id=position_id).first()
    if position is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss position'}}), 200
    marks = Marks.query.filter_by(belongUserId=user_id, goodsId=goods_id).first()
    if marks is not None:
        return jsonify({"result": {"error_code": 1, "msg": '已经标注过了呢'}}), 200
    marks = Marks(belongUserId=user_id, belongGroupId=user.defaultGroupId, spaceId=position.spaceId,
                  positionId=position_id, goodsId=goods_id, isPublic=is_public)
    marks.createdAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    marks.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.add(marks)
    db.session.commit()
    if goods_id != -1 and goods_id is not None:
        save_news(user, title="", content="", type=2, space_id=position.spaceId, position_id=position_id,
                  goods_id=goods_id)
    return jsonify({"objectId": str(marks.id)})


def query_marks(session_token, skip, limit, params):
    """
    查询有权限对组， TODO 关联查询
    :param params:
    :param limit:
    :param skip:
    :param session_token:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss user'}}), 200
    query = db.session.query(Marks, User).filter(Marks.belongUserId == User.id).filter(Marks.isDisable == 0)
    if params is None:
        params = {}
    if "belongGroupId" in params:
        query = query.filter(Marks.belongGroupId == params["belongGroupId"])
    if "spaceId" in params:
        query = query.filter(Marks.spaceId == params["spaceId"])
    if "positionId" in params:
        query = query.filter(Marks.positionId == params["positionId"])
    if "goodsId" in params:
        query = query.filter(Marks.goodsId == params["goodsId"])
    if "objectId" in params:
        query = query.filter(Marks.id == params["objectId"])
    query = query.order_by(desc(Marks.id)).limit(limit).offset(skip).all()
    results = []
    for data, user in query:
        results.append({"objectId": data.id,
                        "belongUserId": data.belongUserId,
                        "belongUserName": user.lastName + user.firstName,
                        "avatar": user.avatar,
                        "belongGroupId": data.belongGroupId,
                        "spaceId": data.spaceId,
                        "positionId": data.positionId,
                        "goodsId": data.goodsId,
                        "isPublic": data.isPublic,
                        "createdAt": util.get_iso8601_from_dt(data.createdAt),
                        "updatedAt": util.get_iso8601_from_dt(data.updatedAt), })
    return jsonify({"results": results})


def update_marks(session_token, todo_id, is_public, is_disable):
    """
    更新一条项目记录
    :param is_disable:
    :param session_token:
    :param todo_id:
    :param is_public:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss user'}}), 200
    marks = Marks.query.filter_by(id=todo_id, belongUserId=user_id).first()
    if marks is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss marks'}}), 200
    if is_public is not None:
        marks.isPublic = is_public
    if is_disable is not None:
        marks.isDisable = is_disable
    marks.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.commit()
    return jsonify({"result": {"data": {}, "error_code": 0, "msg": "项目修改成功"}})


def save_news(user, title="", content="", type=1, space_id=-1, position_id=-1, goods_id=-1):
    """
    type
        1 添加物品
        2 标记物品
        3 备注
    :param user:
    :param title:
    :param content:
    :param type:
    :param space_id:
    :param position_id:
    :param goods_id:
    :return:
    """
    space = Space.query.filter_by(id=space_id).first()
    if space is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss space'}}), 200
    position = Position.query.filter_by(id=position_id).first()
    if position is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss position'}}), 200
    goods = Goods.query.filter_by(id=goods_id).first()
    if goods_id != -1 and space is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss goods'}}), 200
    avatar = ""
    if type == 1:
        title = "{} 在 #{}/{} 添加了{}".format(user.lastName + user.firstName, space.name, position.name, goods.name)
        avatar = goods.avatar
    elif type == 2:
        title = "{} 标记了{}".format(user.lastName + user.firstName, goods.name)
        avatar = goods.avatar
    elif type == 3:
        title = "{} 添加了备注".format(user.lastName + user.firstName)
        avatar = goods.avatar
    elif type == 4:
        title = "{} 在 #{} 添加了{}".format(user.lastName + user.firstName, space.name, position.name)
        avatar = space.avatar
    news = News(title=title, content=content, type=type, belongUserId=user.id,
                belongGroupId=space.belongGroupId, spaceId=space_id,
                positionId=position_id, goodsId=goods_id, avatar=avatar)
    news.createdAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    news.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.add(news)
    db.session.commit()


def query_news(session_token, skip, limit, params):
    """
    查询有权限对组， belongGroupId, spaceId, positionId, goodsId,
    :param params:
    :param limit:
    :param skip:
    :param session_token:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss user'}}), 200
    # sub_qry = db.session.query(func.count(Reads.id).label("read_flag")).filter(
    #     Reads.newsId == News.id).filter(Reads.belongUserId == user_id).correlate(News).as_scalar()
    query = db.session.query(News, User, Space, Position).filter(News.isDisable == 0) \
        .filter(News.belongUserId == User.id) \
        .filter(News.spaceId == Space.id) \
        .filter(News.positionId == Position.id) \
        .filter(News.goodsId == Goods.id) \
        .filter(Goods.isDisable == 0) \
        .filter(not_(exists().where(and_(News.id == Reads.newsId, Reads.belongUserId == user_id))))
    if params is None:
        params = {}
    if "belongGroupId" in params:
        query = query.filter(News.belongGroupId == params["belongGroupId"])
    if "spaceId" in params:
        query = query.filter(News.spaceId == params["spaceId"])
    if "positionId" in params:
        query = query.filter(News.positionId == params["positionId"])
    if "goodsId" in params:
        query = query.filter(News.goodsId == params["goodsId"])
    if "type" in params:
        query = query.filter(News.type == params["type"])
    if "objectId" in params:
        query = query.filter(News.id == params["objectId"])

    query = query.order_by(desc(News.id)).limit(limit).offset(skip).all()
    results = []
    for data, user, space, position in query:
        if data.type == 4:
            content = "# 共{}个物品 #".format(get_goods_num_in_position(data.positionId))
        else:
            content = data.content
        results.append({"objectId": data.id,
                        "title": data.title,
                        "content": content,
                        "type": data.type,
                        "avatar": data.avatar,
                        "belongUserId": data.belongGroupId,
                        "belongUserName": user.lastName + user.firstName,
                        "belongGroupId": data.belongGroupId,
                        "spaceId": data.spaceId,
                        "spaceName": space.name,
                        "positionId": data.positionId,
                        "positionName": position.name,
                        "goodsId": data.goodsId,
                        "isPublic": data.isPublic,
                        "createdAt": util.get_iso8601_from_dt(data.createdAt),
                        "updatedAt": util.get_iso8601_from_dt(data.updatedAt), })
    return jsonify({"results": results})


def read_news(session_token, news_id, is_mark):
    """
    标记/已读
    :param session_token:
    :param news_id:
    :param is_mark:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss user'}}), 200
    news = News.query.filter_by(id=news_id).first()
    if news is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss news'}}), 200
    reads = Reads(belongUserId=user_id, newsId=news_id)
    reads.createdAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    reads.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.add(reads)
    db.session.commit()
    if is_mark == 1:
        create_marks(session_token=session_token, is_public=True, position_id=news.positionId, goods_id=news.goodsId)
    return jsonify({"result": {"data": {}, "error_code": 0, "msg": "项目修改成功"}})


def fix_search(session_token, keyword, belong_group_id):
    """
    混合查询，
    :param belong_group_id:
    :param keyword:
    :param session_token:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss user'}}), 200
    # 查询空间数据
    query = db.session.query(Space, User).filter(Space.belongUserId == User.id).filter(
        Space.belongGroupId == user.defaultGroupId) \
        .filter(Space.isDisable == 0)
    query = query.filter(Space.belongGroupId == belong_group_id).filter(Space.name.like(f"%{keyword}%"))
    # 私密性
    query = query.filter(or_(
        Space.isPublic == 1, and_(
            Space.isPublic == 0,
            Space.belongUserId == user_id)
    ))

    query = query.all()
    space_results = []
    for data, user in query:
        space_results.append({"objectId": data.id,
                              "name": data.name,
                              "avatar": data.avatar,
                              "belongUserId": data.belongUserId,
                              "belongUserName": user.lastName,
                              "belongGroupId": data.belongGroupId,
                              "positionNum": get_position_num_in_space(data.id),
                              "goodsNum": get_goods_num_in_space(data.id),
                              "membersNum": get_members_num_in_space(data.id),
                              "isPublic": data.isPublic,
                              "createdAt": util.get_iso8601_from_dt(data.createdAt),
                              "updatedAt": util.get_iso8601_from_dt(data.updatedAt), })

    # 查询位置数据
    query = db.session.query(Position, User, Space) \
        .filter(Position.spaceId == Space.id).filter(Position.belongUserId == User.id)
    query = query.filter(Space.belongGroupId == belong_group_id).filter(Position.name.like(f"%{keyword}%"))
    # 私密性
    query = query.filter(or_(
        Position.isPublic == 1, and_(
            Position.isPublic == 0,
            Position.belongUserId == user_id)
    ))
    query = query.filter(Position.isDisable == 0).all()
    position_results = []
    for data, user, space in query:
        position_results.append({"objectId": data.id,
                                 "name": data.name,
                                 "avatar": data.avatar,
                                 "coordinate": data.coordinate,
                                 "belongUserId": data.belongUserId,
                                 "belongGroupId": data.belongGroupId,
                                 "spaceId": data.spaceId,
                                 "belongUserName": user.lastName,
                                 "spaceName": space.name,
                                 "goodsNum": get_goods_num_in_position(data.spaceId),
                                 "membersNum": get_members_num_in_position(data.spaceId),
                                 "isPublic": data.isPublic,
                                 "createdAt": util.get_iso8601_from_dt(data.createdAt),
                                 "updatedAt": util.get_iso8601_from_dt(data.updatedAt), })

    query = db.session.query(Goods, Space, User, Position).filter(Goods.spaceId == Space.id) \
        .filter(Goods.belongUserId == User.id) \
        .filter(Goods.positionId == Position.id)
    query = query.filter(Space.belongGroupId == belong_group_id).filter(Goods.name.like(f"%{keyword}%"))
    query = query.filter(Goods.isDisable == 0)
    # 私密性
    query = query.filter(or_(
        Goods.isPublic == 1, and_(
            Goods.isPublic == 0,
            Goods.belongUserId == user_id)
    ))
    query = query.order_by(desc(Goods.id)).all()
    goods_results = []
    for data, space, user, position in query:
        goods_results.append({"objectId": data.id,
                              "name": data.name,
                              "avatar": data.avatar,
                              "coordinate": data.coordinate,
                              "belongUserId": data.belongUserId,
                              "belongUserName": user.lastName + user.firstName,
                              "belongGroupId": data.belongGroupId,
                              "spaceId": data.spaceId,
                              "spaceName": space.name,
                              "positionId": data.positionId,
                              "positionName": position.name,
                              "type": data.type,
                              "isPublic": data.isPublic,
                              "note": get_latest_note_in_goods(data.id),
                              "marksNum": get_marks_num_in_goods(data.id),
                              "newsNum": get_news_num_in_goods(data.id),
                              "createdAt": util.get_iso8601_from_dt(data.createdAt),
                              "updatedAt": util.get_iso8601_from_dt(data.updatedAt), })

    return jsonify({"result": {
        "data": {"space_results": space_results, "position_results": position_results, "goods_results": goods_results},
        "error_code": 0, "msg": "查询成功"}})
