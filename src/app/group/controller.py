#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 18-6-20 上午10:32
# @Author  : Skye
# @Site    : 
# @File    : views.py
# @Software: PyCharm
import random

from flask import jsonify

from src.app.main import db
from src.app.models.model import User, Group, GroupUser
from src.app.util import util
from src.app.util.mail import APP_SECRET


def create_group(session_token, name, is_public, avatar, desc, return_type="jsonify"):
    """
    创建组，并创建一条关联记录
    :param return_type:
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
    group = Group(name=name, avatar=avatar, desc=desc, belongUserId=user_id, isPublic=is_public)
    group.createdAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    group.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.add(group)
    db.session.commit()
    group_user = GroupUser(userId=user_id, groupId=group.id)
    group_user.isAudit = 1
    group_user.createdAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    group_user.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.add(group_user)
    db.session.commit()
    if return_type == "jsonify":
        return jsonify({"objectId": str(group.id)})
    else:
        return {"result": {"data": {"groupId": group.id}, "error_code": 0, "msg": "项目创建成功"}}


def query_group(session_token, skip, limit, params):
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
        return jsonify({"result": {"error_code": 1, "msg": 'miss userk'}}), 200
    query = db.session.query(Group, User).filter(GroupUser.userId == user_id).filter(
        GroupUser.groupId == Group.id).filter(
        Group.belongUserId == User.id).filter(
        GroupUser.isDisable == 0).filter(
        GroupUser.isAudit == 1).limit(limit).offset(skip).all()
    results = []
    for group, user in query:
        results.append({"objectId": group.id,
                        "name": group.name,
                        "avatar": group.avatar,
                        "desc": group.desc,
                        "belongUserId": group.belongUserId,
                        "belongUserName": user.lastName + user.firstName,
                        "isPublic": group.isPublic,
                        "createdAt": util.get_iso8601_from_dt(group.createdAt),
                        "updatedAt": util.get_iso8601_from_dt(group.updatedAt), })
    return jsonify({"results": results})


def update_group(session_token, todo_id, name, is_public, avatar, desc, is_disable, belong_user_id):
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
    group = Group.query.filter_by(id=todo_id, belongUserId=user_id).first()
    if group is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss group'}}), 200
    if name != "":
        group.name = name
    if is_public is not None:
        group.isPublic = is_public
    if avatar != "":
        group.avatar = avatar
    if desc != "":
        group.desc = desc
    if is_disable is not None:
        group.isDisable = is_disable
    if belong_user_id != -1:
        group.belongUserId = belong_user_id
    group.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.commit()
    return jsonify({"result": {"data": {}, "error_code": 0, "msg": "项目修改成功"}})


def create_invite_code(session_token, group_id):
    """
    创建邀请码
    todo 时效性 唯一性
    :param session_token:
    :param group_id:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss user'}}), 200
    group = Group.query.filter_by(id=group_id, belongUserId=user_id).first()
    if group is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss group'}}), 200
    group.checkCode = str(random.randint(1000, 9999))
    group.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.commit()
    return jsonify({"result": {"data": {"checkCode": group.checkCode}, "error_code": 0, "msg": "邀请码创建成功"}})


def join_group(session_token, check_code):
    """
    加入组
    :param session_token:
    :param check_code:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss user'}}), 200
    group = Group.query.filter_by(checkCode=check_code).first()
    if group is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss group'}}), 200
    group_user = GroupUser.query.filter_by(userId=user_id, groupId=group.id).filter(
        GroupUser.isDisable == 0).first()
    if group_user:
        return jsonify({"result": {"error_code": 1, "msg": 'you have been joined'}}), 200
    else:
        group_user = GroupUser(userId=user_id, groupId=group.id)
        group_user.createdAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
        group_user.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
        group_user.isAudit = 0
        db.session.add(group_user)
        group.checkCode = ""
        db.session.commit()
        return jsonify({"result": {"data": {}, "error_code": 0, "msg": "项目加入成功"}})


def query_group_user(session_token, skip, limit, params):
    """
    查询分组用户
    :param session_token:
    :param skip:
    :param limit:
    :param params:
    :return:
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss userk'}}), 200
    query = db.session.query(User, GroupUser).filter(GroupUser.groupId == params["groupId"]).filter(
        GroupUser.userId == User.id).filter(
        GroupUser.isDisable == 0)
    if "isAudit" in params:
        query = query.filter(GroupUser.isAudit == params["isAudit"])
    query = query.limit(limit).offset(skip).all()
    results = []
    for user, group_user in query:
        results.append({"objectId": group_user.id,
                        "name": user.lastName + user.firstName,
                        "avatar": user.avatar,
                        "userId": group_user.userId,
                        "groupId": group_user.groupId,
                        "isAudit": group_user.isAudit,
                        "createdAt": util.get_iso8601_from_dt(group_user.createdAt),
                        "updatedAt": util.get_iso8601_from_dt(group_user.updatedAt), })
    return jsonify({"results": results})


def update_group_user(session_token, todo_id, is_disable, is_audit):
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss user'}}), 200
    group_user = GroupUser.query.filter_by(id=todo_id).first()
    if group_user is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss group_user'}}), 200
    if is_disable is not None:
        group_user.isDisable = is_disable
    if is_audit is not None:
        print(is_audit)
        print(group_user.isAudit)
        group_user.isAudit = is_audit
        print(group_user.isAudit)
    group_user.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.commit()
    return jsonify({"result": {"data": {}, "error_code": 0, "msg": "项目修改成功"}})
