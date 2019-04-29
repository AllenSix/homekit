#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 18-6-20 上午10:52
# @Author  : Skye
# @Site    : 
# @File    : test_user.py
# @Software: PyCharm
import logging
import os
from unittest import TestCase

import leancloud
from leancloud import cloudfunc

from src.unittest import LEANCLOUD_API_SERVER

session_token = "eyJhbGciOiJIUzI1NiIsImlhdCI6MTUyOTkzMjA5MCwiZXhwIjoxNTMzNTMyMDkwfQ.IjIi.0h1gcx6w8d5W4YDEjY1x9qJIvNdurUiRd3_k_TqQeR4"


class TestGroup(TestCase):

    def setUp(self):
        os.environ.setdefault('LEANCLOUD_API_SERVER', LEANCLOUD_API_SERVER)
        leancloud.init("3G47drEAaXtmQas7U4WxEmx4-gzGzoHsz", "x3cl6OYR2mC6dDQsW0dMeceJ")

        logging.basicConfig(level=logging.DEBUG)

    def test_create_group(self):
        user = leancloud.User().become(session_token)
        print(user.dump())
        Group = leancloud.Object.extend('Group')
        group = Group()
        group.set("name", "测试项目2")
        group.set("isPublic", 1)
        group.set("avatar", "http://www.baidu.com")
        group.set("desc", "项目简介2")
        group.save()

    def test_query_group(self):
        user = leancloud.User().become(session_token)
        Group = leancloud.Object.extend('Group')
        query = Group.query
        query.skip(1)
        query.limit(2)
        todo_list = query.find()
        for todo in todo_list:
            print(todo.dump())

    def test_update_group(self):
        user = leancloud.User().become(session_token)
        Group = leancloud.Object.extend('Group')
        group = Group.create_without_data(2)
        group.set("desc", "测试修改")
        group.save()

    def test_create_invite_code(self):
        user = leancloud.User().become(session_token)
        ret = cloudfunc.run('createInviteCode', groupId=2)
        print(ret)
        assert (type(ret) == dict)

    def test_join_group(self):
        user = leancloud.User().become(
            "eyJhbGciOiJIUzI1NiIsImlhdCI6MTUyOTkxNTQyMywiZXhwIjoxNTMzNTE1NDIzfQ.IjQi.ttcDTMSAszLP7F3TJieiCCzYV6j0o0D8pMFgnMkGCwI")
        ret = cloudfunc.run('joinGroup', checkCode="4675")
        print(ret)
        assert (type(ret) == dict)
