#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 18-6-20 上午10:32
# @Author  : Skye
# @Site    : 
# @File    : views.py
# @Software: PyCharm

from flask import request, jsonify

from src.app.group import controller, group
from src.app.util import util


@group.route('/classes/Group', methods=['POST', ])
def create_group():
    """
    创建组
    :return:
    """
    session_token = request.headers.get('X-LC-Session', "")
    if session_token == "" or session_token is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss session_token'}}), 200
    name = request.json.get('name', "")
    if name == "":
        return jsonify({"result": {"error_code": 1, "msg": 'miss name'}}), 200
    is_public = request.json.get('isPublic', None)
    avatar = request.json.get('avatar', "")
    desc = request.json.get('desc', "")
    return controller.create_group(session_token, name, is_public, avatar, desc)


@group.route('/classes/Group', methods=['GET', ])
def query_group():
    """
    查询组
    :return:
    """
    session_token = request.headers.get('X-LC-Session', "")
    if session_token == "" or session_token is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss session_token'}}), 200
    params = util.parse_get_where_params()
    skip = int(request.args.get('skip', '0'))
    limit = int(request.args.get('limit', '20'))
    return controller.query_group(session_token, skip, limit, params)


@group.route('/classes/Group/<int:todo_id>', methods=['PUT', ])
def update_group(todo_id):
    """
    查询组
    :return:
    """
    session_token = request.headers.get('X-LC-Session', "")
    if session_token == "" or session_token is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss session_token'}}), 200
    name = request.json.get('name', "")
    is_public = request.json.get('isPublic', None)
    avatar = request.json.get('avatar', "")
    desc = request.json.get('desc', "")
    belong_user_id = request.json.get('belongUserId', -1)
    is_disable = request.json.get('isDisable', None)
    return controller.update_group(session_token, todo_id, name, is_public, avatar, desc, is_disable, belong_user_id)


@group.route('/functions/createInviteCode', methods=['POST', ])
def create_invite_code():
    """
    创建邀请码
    :return:
    """
    session_token = request.headers.get('X-LC-Session', "")
    if session_token == "" or session_token is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss session_token'}}), 200
    group_id = request.json.get('groupId', -1)
    if group_id == -1:
        return jsonify({"result": {"error_code": 1, "msg": 'miss groupId'}}), 200
    return controller.create_invite_code(session_token, group_id)


@group.route('/functions/joinGroup', methods=['POST', ])
def join_group():
    """
    加入组
    :return:
    """
    session_token = request.headers.get('X-LC-Session', "")
    if session_token == "" or session_token is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss session_token'}}), 200
    check_code = request.json.get('checkCode', "")
    if check_code == "":
        return jsonify({"result": {"error_code": 1, "msg": 'miss checkCode'}}), 200
    return controller.join_group(session_token, check_code)


@group.route('/classes/GroupUser', methods=['GET', ])
def query_group_user():
    """
    查询分组用户
    :return:
    """
    session_token = request.headers.get('X-LC-Session', "")
    if session_token == "" or session_token is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss session_token'}}), 200
    params = util.parse_get_where_params()
    skip = int(request.args.get('skip', '0'))
    limit = int(request.args.get('limit', '20'))
    return controller.query_group_user(session_token, skip, limit, params)


@group.route('/classes/GroupUser/<int:todo_id>', methods=['PUT', ])
def update_group_user(todo_id):
    """
    更新分組
    :return:
    """
    session_token = request.headers.get('X-LC-Session', "")
    if session_token == "" or session_token is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss session_token'}}), 200
    is_audit = request.json.get('isAudit', None)
    is_disable = request.json.get('isDisable', None)
    return controller.update_group_user(session_token, todo_id, is_disable, is_audit)
