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


class TestUser(TestCase):

    def setUp(self):
        os.environ.setdefault('LEANCLOUD_API_SERVER', LEANCLOUD_API_SERVER)
        leancloud.init("3G47drEAaXtmQas7U4WxEmx4-gzGzoHsz", "x3cl6OYR2mC6dDQsW0dMeceJ")

        logging.basicConfig(level=logging.DEBUG)

    def test_send_code_by_email(self):
        ret = cloudfunc.run('sendCodeByEmail', username="zxh@zqf.com.cn")
        print(ret)
        assert (type(ret) == dict)

    def test_register(self):
        ret = cloudfunc.run('register', username="zxh@zqf.com.cn", checkCode="5255",
                            password="123456", firstName="晓华", lastName="zheng", email="zxh@zqf.com.cn",
                            avatar="https://www.gravatar.com/avatar/0efa74fe76da7681da2939b3214e5cdf?s=328&d=identicon&r=PG", )
        print(ret)
        assert (type(ret) == dict)

    def test_become(self):
        user = leancloud.User().become(session_token)
        print(user.dump())

    def test_reset_pwd(self):
        ret = cloudfunc.run('resetPassword', username="zxh@zqf.com.cn", checkCode="5850",
                            password="111111")
        print(ret)

    def test_modify_user(self):
        user = leancloud.User().become(session_token)
        print(user.dump())
        ret = cloudfunc.run('modifyUserInfo', password="123456", firstName="晓华", lastName="郑",
                            email="zxh@zqf.com.cn1", defaultGroupId=2,
                            avatar="https://www.gravatar.com/avatar/0efa74fe76da7681da2939b3214e5cdf?s=328&d=identicon&r=PG", )
        print(ret)
        assert (type(ret) == dict)

    def test_login(self):
        user = leancloud.User()
        user.login("zxh@zqf.com.cn", "123456")
        print(user.dump())
