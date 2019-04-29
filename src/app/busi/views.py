#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 18-6-20 上午10:32
# @Author  : Skye
# @Site    : 
# @File    : views.py
# @Software: PyCharm
import json
import logging

from flask import request, jsonify, make_response
from werkzeug.exceptions import NotFound

from src.app.busi import controller, busi
from src.app.util import util


@busi.route('/classes/Space', methods=['POST', ])
def create_space():
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
    group_id = request.json.get('belongGroupId', -1)
    if group_id == -1:
        return jsonify({"result": {"error_code": 1, "msg": 'miss belongGroupId'}}), 200
    return controller.create_space(session_token, name, is_public, avatar, group_id)


@busi.route('/classes/Space', methods=['GET', ])
def query_space():
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
    return controller.query_space(session_token, skip, limit, params)


@busi.route('/classes/Space/<int:todo_id>', methods=['PUT', ])
def update_space(todo_id):
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
    is_disable = request.json.get('isDisable', None)
    return controller.update_space(session_token, todo_id, name, is_public, avatar, is_disable)


@busi.route('/classes/Position', methods=['POST', ])
def create_position():
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
    coordinate = request.json.get('coordinate', "")
    space_id = request.json.get('spaceId', "")
    if space_id == -1:
        return jsonify({"result": {"error_code": 1, "msg": 'miss spaceId'}}), 200
    return controller.create_position(session_token, name, is_public, avatar, space_id, coordinate)


@busi.route('/classes/Position', methods=['GET', ])
def query_position():
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
    return controller.query_position(session_token, skip, limit, params)


@busi.route('/classes/Position/<int:todo_id>', methods=['PUT', ])
def update_position(todo_id):
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
    coordinate = request.json.get('coordinate', "")
    is_disable = request.json.get('isDisable', None)
    return controller.update_position(session_token, todo_id, name, is_public, avatar, coordinate, is_disable)


@busi.route('/classes/Goods', methods=['POST', ])
def create_goods():
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
    coordinate = request.json.get('coordinate', "")
    position_id = request.json.get('positionId', "")
    internal_id = request.json.get('__internalId', "")
    type = request.json.get('type', 1)
    if position_id == -1:
        return jsonify({"result": {"error_code": 1, "msg": 'miss positionId'}}), 200
    return controller.create_goods(session_token, name, is_public, avatar, coordinate, position_id, type, internal_id)


@busi.route('/classes/Goods', methods=['GET', ])
def query_goods():
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
    return controller.query_goods(session_token, skip, limit, params)


@busi.route('/classes/Goods/<int:todo_id>', methods=['PUT', ])
def update_goods(todo_id):
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
    is_disable = request.json.get('isDisable', None)
    coordinate = request.json.get('coordinate', "")
    return controller.update_goods(session_token, todo_id, name, is_public, avatar, desc, is_disable, coordinate)


@busi.route('/classes/Notes', methods=['POST', ])
def create_notes():
    """
    创建组
    :return:
    """
    session_token = request.headers.get('X-LC-Session', "")
    if session_token == "" or session_token is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss session_token'}}), 200
    note = request.json.get('note', "")
    if note == "":
        return jsonify({"result": {"error_code": 1, "msg": 'miss note'}}), 200
    is_public = request.json.get('isPublic', None)
    goods_id = request.json.get('goodsId', -1)
    if goods_id == -1:
        return jsonify({"result": {"error_code": 1, "msg": 'miss goodsId'}}), 200
    return controller.create_notes(session_token, note, is_public, goods_id)


@busi.route('/classes/Notes', methods=['GET', ])
def query_notes():
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
    return controller.query_notes(session_token, skip, limit, params)


@busi.route('/classes/Notes/<int:todo_id>', methods=['PUT', ])
def update_notes(todo_id):
    """
    查询组
    :return:
    """
    session_token = request.headers.get('X-LC-Session', "")
    if session_token == "" or session_token is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss session_token'}}), 200
    note = request.json.get('note', "")
    is_public = request.json.get('isPublic', None)
    is_disable = request.json.get('isDisable', None)
    return controller.update_notes(session_token, todo_id, note, is_public, is_disable)


@busi.route('/classes/Marks', methods=['POST', ])
def create_marks():
    """
    创建组
    :return:
    """
    session_token = request.headers.get('X-LC-Session', "")
    if session_token == "" or session_token is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss session_token'}}), 200
    position_id = request.json.get('positionId', -1)
    if position_id == -1:
        return jsonify({"result": {"error_code": 1, "msg": 'miss positionId'}}), 200
    goods_id = request.json.get('goodsId', -1)
    is_public = request.json.get('isPublic', None)

    return controller.create_marks(session_token, is_public, position_id, goods_id)


@busi.route('/classes/Marks', methods=['GET', ])
def query_marks():
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
    return controller.query_marks(session_token, skip, limit, params)


@busi.route('/classes/Marks/<int:todo_id>', methods=['PUT', ])
def update_marks(todo_id):
    """
    查询组
    :return:
    """
    session_token = request.headers.get('X-LC-Session', "")
    if session_token == "" or session_token is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss session_token'}}), 200
    is_public = request.json.get('isPublic', None)
    is_disable = request.json.get('isDisable', None)
    return controller.update_marks(session_token, todo_id, is_public, is_disable)


@busi.route('/classes/News', methods=['GET', ])
def query_news():
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
    return controller.query_news(session_token, skip, limit, params)


@busi.route('/functions/readNews', methods=['POST', ])
def read_news():
    """
    动态已读
    :return:
    """
    session_token = request.headers.get('X-LC-Session', "")
    if session_token == "" or session_token is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss session_token'}}), 200
    is_mark = request.json.get('isMark', 0)
    news_id = request.json.get('newsId', None)
    return controller.read_news(session_token, news_id, is_mark)


@busi.route('/batch/save', methods=['POST'])
def batch_save():
    """
    批量保存，主要是ios sdk 使用
    Execute multiple requests, submitted as a batch.

    :statuscode 207: Multi status
    """
    header_dict = {}
    responses = []
    for (k, v) in request.headers.items():
        header_dict[k] = v
    from src.app.main import app
    for req in request.json.get('requests', None):
        method = req['method']
        path = req['path']
        body = req.get('body', None)
        params = req.get('params', None)
        if params is not None and "where" in params:
            params["where"] = json.dumps(params["where"])

        with app.app_context():
            with app.test_request_context(path, method=method, headers=header_dict, data=json.dumps(body),
                                          query_string=params,
                                          content_type='application/json'):
                try:
                    rv = app.preprocess_request()
                    if rv is None:
                        rv = app.dispatch_request()
                except NotFound as e:
                    rv = app.handle_user_exception(e)
                    return make_response("{}", 400, {'Content-Type': 'application/json'})
                except Exception as e:
                    rv = app.handle_user_exception(e)
                response = app.make_response(rv)
                response = app.process_response(response)

        respstr = _read_response(response)
        responses.append({
            "status": response.status_code,
            "response": _read_response(response)
        })
        __internalId = body.get("__internalId")
        retdict = json.loads(respstr)
        if path == '/1.1/users':
            logging.debug("batch save 1.1 users")
        else:
            logging.debug("other save")
            respstr = json.dumps({__internalId: retdict})
            retdict[__internalId] = retdict

    return make_response(respstr, response.status_code, {'Content-Type': 'application/json'})


@busi.route('/batch/save1', methods=['POST', ])
def update_route():
    """
    查询组
    :return:
    """
    header_dict = {}
    retarray = []
    for (k, v) in request.headers.items():
        header_dict[k] = v
    from src.app.main import app
    for req in request.json.get('requests', None):
        method = req['method']
        path = req['path']
        body = req.get('body', None)
        params = req.get('params', None)
        if params is not None and "where" in params:
            params["where"] = json.dumps(params["where"])
        with app.app_context():
            with app.test_request_context(path, method=method, headers=header_dict, data=json.dumps(body),
                                          query_string=params,
                                          content_type='application/json'):
                try:
                    rv = app.preprocess_request()
                    if rv is None:
                        rv = app.dispatch_request()
                except NotFound as e:
                    rv = app.handle_user_exception(e)
                    return make_response("{}", 400, {'Content-Type': 'application/json'})
                except Exception as e:
                    rv = app.handle_user_exception(e)
                response = app.make_response(rv)
                response = app.process_response(response)
        respstr = _read_response(response)
        retdict = json.loads(respstr)

        retarray.append({"success": retdict})
    respstr = json.dumps(retarray)
    return make_response(respstr, response.status_code, {'Content-Type': 'application/json'})


def _read_response(response):
    from io import StringIO
    output = StringIO()
    try:
        for line in response.response:
            output.write(line.decode("utf8"))
        return output.getvalue()

    finally:
        output.close()


@busi.route('/classes/Helps', methods=['GET', ])
def query_helps():
    """
    查询组
    :return:
    """
    return jsonify({"results": [{"url": "https://sundries.gitbook.io/help/"}]})


@busi.route('/functions/search', methods=['POST', ])
def fix_search():
    """
    混合查询
    :return:
    """
    session_token = request.headers.get('X-LC-Session', "")
    if session_token == "" or session_token is None:
        return jsonify({"result": {"error_code": 1, "msg": 'miss session_token'}}), 200
    keyword = request.json.get('keyword', "")
    if keyword == "":
        return jsonify({"result": {"error_code": 1, "msg": 'miss keyword'}}), 200
    belong_group_id = request.json.get('belongGroupId', "")
    if belong_group_id == "":
        return jsonify({"result": {"error_code": 1, "msg": 'miss belongGroupId'}}), 200
    return controller.fix_search(session_token, keyword, belong_group_id)
