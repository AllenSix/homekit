#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 18-6-13 下午2:43
# @Author  : Skye
# @Site    : 
# @File    : __init__.py.py
# @Software: PyCharm

from flask import Blueprint

user = Blueprint('user', __name__, )

from src.app.user import views
