#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 18-6-20 下午3:29
# @Author  : Skye
# @Site    : 
# @File    : __init__.py.py
# @Software: PyCharm

from flask import Blueprint

busi = Blueprint('busi', __name__, )

from src.app.busi import views
