#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 18-6-20 下午3:29
# @Author  : Skye
# @Site    : 
# @File    : __init__.py.py
# @Software: PyCharm

from flask import Blueprint

group = Blueprint('group', __name__, )

from src.app.group import views
