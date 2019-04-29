#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 18-6-20 下午3:28
# @Author  : Skye
# @Site    : 
# @File    : __init__.py.py
# @Software: PyCharm
from flask import Blueprint

file = Blueprint('file', __name__, )

from src.app.file import views
