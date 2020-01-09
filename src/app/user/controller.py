#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 18-6-20 上午10:32
# @Author  : Skye
# @Site    : 
# @File    : views.py
# @Software: PyCharm

import random
import time

from flask import jsonify

from src.app.group.controller import create_group
from src.app.main import db
from src.app.models.model import User
from src.app.util import util
from src.app.util.mail import send_email, APP_SECRET


def send_code_by_email(username=""):
    """
    1.查找用户表指定用户，如无数据则添加一条数据
    2.生成4位随机数，发送邮件
    :param username:
    :return:
    """
    user = User.query.filter_by(username=username).first()
    if user is None:
        user = User(username=username, email=username)
        db.session.add(user)
        user.codeExpiredAt = 0
        user.createdAt = util.get_mysql_datetime_from_iso(util.get_iso8601())

    # 判断发送邮件间隔
    if user.codeExpiredAt > int(time.time()):
        return jsonify({"result": {"error_code": 1, "msg": '连续发送邮件必须间隔一分钟'}}), 200

    user.checkCode = str(random.randint(1000, 9999))
    user.codeExpiredAt = int(time.time()) + 60
    user.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.commit()
    send_email("NANA验证码邮件", "您的验证码为{}".format(user.checkCode), username)
    return jsonify({"result": {"data": {}, "error_code": 0, "msg": "邮件发送成功"}})


def query_email(username=""):
    """
    1.查找用户表指定用户
    :param username:
    :return:
    """
    user = User.query.filter_by(username=username).first()
    # 密码不为空才判断为成功注册
    if user is not None and user.password:
        return jsonify({"result": {"error_code": 1, "msg": '邮箱已存在'}}), 200
    return jsonify({"result": {"data": {}, "error_code": 0, "msg": "邮箱不存在"}})


def register(first_name="", last_name="", username="", email="", check_code="", password="", avatar="", ):
    """
    注册接口
    """
    user = User.query.filter_by(username=username).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": '验证码不存在'}}), 200
    if user.checkCode != check_code:
        return jsonify({"result": {"error_code": 1, "msg": '验证码不正确'}}), 200
    user.checkCode = ""
    user.codeExpiredAt = 0
    if user.password is not None:
        return jsonify({"result": {"error_code": 1, "msg": '用户已注册'}}), 200
    user.firstName = first_name
    user.lastName = last_name
    user.password = util.get_md5(password)
    user.avatar = avatar
    user.sessionToken = util.generate_auth_token(APP_SECRET, user.id)
    user.createdAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    user.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.commit()
    ret = create_group(user.sessionToken, "未命名群组", False, "", "未填写备注", return_type="json")
    user.defaultGroupId = ret["result"]["data"]["groupId"]
    db.session.commit()
    return jsonify({"result": {
        "data": {"sessionToken": user.sessionToken}, "error_code": 0, "msg": "注册成功"}})


def reset_password(username="", check_code="", password=""):
    """
    重置密码接口
    """
    user = User.query.filter_by(username=username).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": '验证码不存在'}}), 200
    if user.checkCode != check_code:
        return jsonify({"result": {"error_code": 1, "msg": '验证码不正确'}}), 200
    user.checkCode = ""
    user.codeExpiredAt = 0
    if user.password is None:
        return jsonify({"result": {"error_code": 1, "msg": '用户尚未注册'}}), 200
    user.password = util.get_md5(password)
    user.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.commit()
    return jsonify({"result": {"data": {}, "error_code": 0, "msg": "密码重置成功"}})


def users_me(session_token):
    """
    a.通过sessionToken判断user表是否存在该用户,无则新建有则修改
    b.调用莱卡接口鉴权token /auth/user/token/validate
    :return: jsonify object
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({'code': 1, 'msg': 'miss user'})
    return pack_users_me(user)


def pack_users_me(user):
    """
    把user打包成返回数据
    :param user:
    :return:
    """
    oid = str(user.id)
    user_dict = dict(user.__dict__)
    user_dict['objectId'] = oid
    if "password" in user_dict:
        del user_dict['password']
    del user_dict["_sa_instance_state"]
    del user_dict["checkCode"]
    del user_dict["codeExpiredAt"]
    user_dict['updatedAt'] = util.get_iso8601_from_dt(user_dict['updatedAt'])
    user_dict['createdAt'] = util.get_iso8601_from_dt(user_dict['createdAt'])
    print(user_dict)
    return jsonify(user_dict), 200


def modify_user_info(session_token="", first_name="", last_name="", email="", password="", avatar="",
                     default_group_id=-1):
    """
    修改用户信息接口
    """
    user_id = util.review_auth_token(APP_SECRET, session_token)
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({'code': 1, 'msg': 'miss user'})
    if first_name != "":
        user.firstName = first_name
    if last_name != "":
        user.lastName = last_name
    if email != "":
        user.email = email
    if avatar != "":
        user.avatar = avatar
    if password != "":
        user.password = util.get_md5(password)
    if default_group_id != -1:
        user.defaultGroupId = default_group_id
    user.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.commit()
    return jsonify({"result": {"data": {}, "error_code": 0, "msg": "信息修改成功"}})


def login(username="", password=""):
    """
    登录接口
    """
    user = User.query.filter_by(username=username).first()
    if user is None:
        return jsonify({"result": {"error_code": 1, "msg": '验证码不存在'}}), 200
    if user.password != util.get_md5(password):
        return jsonify({"result": {"error_code": 1, "msg": '密码不正确'}}), 200
    user.sessionToken = util.generate_auth_token(APP_SECRET, user.id)
    user.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    db.session.commit()
    return pack_users_me(user)


def quick_register():
    """
    快速注册接口
    """
    while True:
        username = util.generate_new_user()
        if username.startswith('0'):
            continue
        # 防止重名
        count = User.query.filter_by(username=username).count()
        if count == 0:
            break
    user = User(username=username, password=util.get_md5('123456'), email=username)
    db.session.add(user)
    db.session.flush()
    user.codeExpiredAt = 0
    user.createdAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    user.updatedAt = util.get_mysql_datetime_from_iso(util.get_iso8601())
    user.sessionToken = util.generate_auth_token(APP_SECRET, user.id)
    db.session.commit()
    ret = create_group(user.sessionToken, "未命名群组", False, "", "未填写备注", return_type="json")
    user.defaultGroupId = ret["result"]["data"]["groupId"]
    db.session.commit()
    return jsonify({"result": {
        "data": {"sessionToken": user.sessionToken, "username": username, "password": "123456"},
        "error_code": 0, "msg": "注册成功"}})
