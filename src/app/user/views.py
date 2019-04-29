#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 18-6-20 上午10:32
# @Author  : Skye
# @Site    : 
# @File    : views.py
# @Software: PyCharm
import json

from flask import request, jsonify

from src.app.user import user, controller


@user.route('/functions/sendCodeByEmail', methods=['POST', ])
def send_code_by_email():
    """
    :return:
    """
    username = request.json.get('username', "")
    if username == "":
        return jsonify({"result": {"error_code": 1, "msg": 'miss username'}}), 200
    return controller.send_code_by_email(username=username)


@user.route('/functions/queryEmail', methods=['POST', ])
def query_email():
    """
    :return:
    """
    username = request.json.get('username', "")
    if username == "":
        return jsonify({"result": {"error_code": 1, "msg": 'miss username'}}), 200
    return controller.query_email(username=username)


@user.route('/functions/register', methods=['POST', ])
def register():
    """
    注册接口
    :return:
    """
    username = request.json.get('username', "")
    if username == "":
        return jsonify({"result": {"error_code": 1, "msg": 'miss username'}}), 200
    check_code = request.json.get('checkCode', "")
    if check_code == "":
        return jsonify({"result": {"error_code": 1, "msg": 'miss check_code'}}), 200
    password = request.json.get('password', "")
    if password == "":
        return jsonify({"result": {"error_code": 1, "msg": 'miss password'}}), 200
    first_name = request.json.get('firstName', "")
    last_name = request.json.get('lastName', "")
    email = request.json.get('email', "")
    avatar = request.json.get('avatar', "")
    return controller.register(first_name=first_name, last_name=last_name, username=username, email=email,
                               check_code=check_code, password=password, avatar=avatar)


@user.route('/users/me', methods=['GET', 'POST'])
def users_me():
    """
    :return:
    """
    session_token = request.headers.get('X-LC-Session', "")
    if session_token == "":
        session_token = request.headers.get('X-AVOSCloud-Session-Token', "")
    if session_token == "":
        session_token = request.args.get('session_token', "")
    if session_token == "":
        param_dict = json.loads(request.data)
        session_token = param_dict.get("session_token")
    if session_token == "" or session_token is None:
        return jsonify({'code': 1, 'msg': 'miss session_token'})
    return controller.users_me(session_token)


@user.route('/functions/resetPassword', methods=['POST', ])
def reset_password():
    """
    重置密码接口
    :return:
    """
    username = request.json.get('username', "")
    if username == "":
        return jsonify({"result": {"error_code": 1, "msg": 'miss username'}}), 200
    check_code = request.json.get('checkCode', "")
    if check_code == "":
        return jsonify({"result": {"error_code": 1, "msg": 'miss check_code'}}), 200
    password = request.json.get('password', "")
    if password == "":
        return jsonify({"result": {"error_code": 1, "msg": 'miss password'}}), 200
    return controller.reset_password(username=username,
                                     check_code=check_code, password=password)


@user.route('/functions/modifyUserInfo', methods=['POST', ])
def modify_user_info():
    """
    修改用户信息接口 todo 修改默认项目
    :return:
    """
    session_token = request.headers.get('X-LC-Session', "")
    if session_token == "" or session_token is None:
        return jsonify({'code': 1, 'msg': 'miss session_token'})
    password = request.json.get('password', "")
    first_name = request.json.get('firstName', "")
    last_name = request.json.get('lastName', "")
    email = request.json.get('email', "")
    avatar = request.json.get('avatar', "")
    default_group_id = request.json.get('defaultGroupId', -1)
    return controller.modify_user_info(session_token=session_token, first_name=first_name, last_name=last_name,
                                       email=email, password=password, avatar=avatar, default_group_id=default_group_id)


@user.route('/login', methods=['POST', ])
def login():
    username = request.json.get('username', "")
    if username == "":
        return jsonify({"result": {"error_code": 1, "msg": 'miss username'}}), 200
    password = request.json.get('password', "")
    if password == "":
        return jsonify({"result": {"error_code": 1, "msg": 'miss password'}}), 200
    return controller.login(username=username, password=password)
