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

session_token = "eyJhbGciOiJIUzI1NiIsImlhdCI6MTUzMDY4MjUxMSwiZXhwIjoxNTM0MjgyNTExfQ.IjQi.MG81MLUELCXuDbPfmqAzpEBzdXLu7dGlPywaa__-16E"


class TestBusi(TestCase):

    def setUp(self):
        os.environ.setdefault('LEANCLOUD_API_SERVER', LEANCLOUD_API_SERVER)
        leancloud.init("3G47drEAaXtmQas7U4WxEmx4-gzGzoHsz", "x3cl6OYR2mC6dDQsW0dMeceJ")

        logging.basicConfig(level=logging.DEBUG)

    def test_create_space(self):
        leancloud.User().become(session_token)
        Model = leancloud.Object.extend('Space')
        obj = Model()
        obj.set("name", "客厅")
        obj.set("isPublic", 1)
        obj.set("avatar", "http://www.baidu.com")
        obj.set("groupId", 2)
        obj.save()

    def test_query_space(self):
        user = leancloud.User().become(session_token)
        Space = leancloud.Object.extend('Space')
        query = Space.query
        query.skip(0)
        query.limit(2)
        todo_list = query.find()
        for todo in todo_list:
            print(todo.dump())

    def test_update_space(self):
        user = leancloud.User().become(session_token)
        Modle = leancloud.Object.extend('Space')
        obj = Modle.create_without_data(1)
        obj.set("isPublic", 0)
        obj.save()

    def test_create_position(self):
        leancloud.User().become(session_token)
        Model = leancloud.Object.extend('Position')
        obj = Model()
        obj.set("name", "入口处")
        obj.set("isPublic", 1)
        obj.set("avatar", "http://www.baidu.com")
        obj.set("coordinate", "coordinatecoordinatecoordinate")
        obj.set("spaceId", 1)
        obj.save()

    def test_query_position(self):
        user = leancloud.User().become(session_token)
        Model = leancloud.Object.extend('Position')
        query = Model.query
        query.skip(0)
        query.limit(2)
        todo_list = query.find()
        for todo in todo_list:
            print(todo.dump())

    def test_update_position(self):
        user = leancloud.User().become(session_token)
        Modle = leancloud.Object.extend('Position')
        obj = Modle.create_without_data(1)
        obj.set("coordinate", "位置")
        obj.save()

    def test_create_goods(self):
        leancloud.User().become(session_token)
        Model = leancloud.Object.extend('Goods')
        obj = Model()
        obj.set("name", "鞋柜2")
        obj.set("isPublic", 1)
        obj.set("avatar", "http://www.baidu.com")
        obj.set("coordinate", "")
        obj.set("positionId", 2)
        obj.set("type", 1)
        obj.save()

        print(obj.dump())

    def test_query_goods(self):
        user = leancloud.User().become(session_token)
        Model = leancloud.Object.extend('Goods')
        query = Model.query
        query.skip(0)
        query.limit(2)
        query.equal_to("type", 2)
        todo_list = query.find()
        for todo in todo_list:
            print(todo.dump())

    def test_update_goods(self):
        user = leancloud.User().become(session_token)
        Modle = leancloud.Object.extend('Goods')
        obj = Modle.create_without_data(1)
        obj.set("coordinate", "位置")
        obj.save()

    def test_create_notes(self):
        leancloud.User().become(session_token)
        Model = leancloud.Object.extend('Notes')
        obj = Model()
        obj.set("note", "这个东西不错，哈哈哈")
        obj.set("isPublic", 1)
        obj.set("goodsId", 1)
        obj.save()

    def test_query_notes(self):
        user = leancloud.User().become(session_token)
        Model = leancloud.Object.extend('Notes')
        query = Model.query
        query.skip(0)
        query.limit(2)
        todo_list = query.find()
        for todo in todo_list:
            print(todo.dump())

    def test_update_notes(self):
        user = leancloud.User().become(session_token)
        Modle = leancloud.Object.extend('Notes')
        obj = Modle.create_without_data(1)
        obj.set("note", "zhengxh")
        obj.save()

    def test_create_marks(self):
        leancloud.User().become(session_token)
        Model = leancloud.Object.extend('Marks')
        obj = Model()
        obj.set("isPublic", 1)
        obj.set("goodsId", 2)
        obj.save()

    def test_query_marks(self):
        user = leancloud.User().become(session_token)
        Model = leancloud.Object.extend('Marks')
        query = Model.query
        query.skip(0)
        query.limit(2)
        todo_list = query.find()
        for todo in todo_list:
            print(todo.dump())

    def test_update_marks(self):
        user = leancloud.User().become(session_token)
        Modle = leancloud.Object.extend('Notes')
        obj = Modle.create_without_data(1)
        obj.set("note", "zhengxh")
        obj.save()

    def test_query_news(self):
        user = leancloud.User().become(session_token)
        Model = leancloud.Object.extend('News')
        query = Model.query
        query.skip(0)
        query.limit(2)
        todo_list = query.find()
        for todo in todo_list:
            print(todo.dump())

    def test_read_news(self):
        user = leancloud.User().become(session_token)
        ret = cloudfunc.run('readNews', isMark=1, newsId=1)
        print(ret)
        assert (type(ret) == dict)

    def test_join_group(self):
        user = leancloud.User().become(
            "eyJhbGciOiJIUzI1NiIsImlhdCI6MTUyOTkxNTQyMywiZXhwIjoxNTMzNTE1NDIzfQ.IjQi.ttcDTMSAszLP7F3TJieiCCzYV6j0o0D8pMFgnMkGCwI")
        ret = cloudfunc.run('search', keyword="4675")
        print(ret)
        assert (type(ret) == dict)

    def test_fix_search(self):
        user = leancloud.User().become(
            "eyJhbGciOiJIUzI1NiIsImlhdCI6MTUyOTkxNTQyMywiZXhwIjoxNTMzNTE1NDIzfQ.IjQi.ttcDTMSAszLP7F3TJieiCCzYV6j0o0D8pMFgnMkGCwI")
        ret = cloudfunc.run('search', keyword="测", belongGroupId="8")
        print(ret)
        assert (type(ret) == dict)
