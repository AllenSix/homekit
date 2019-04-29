#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 18-6-20 上午10:32
# @Author  : Skye
# @Site    : 
# @File    : views.py
# @Software: PyCharm
import json
import logging
import os

from flask import request, jsonify

from src.app.file import file
from src.app.util import qiniucloudfile


@file.route('/fileTokens', methods=['POST'])
@file.route('/qiniu', methods=['POST'])
def qiniufileTokens():
    """
    TODO
    到七牛获取token并返回
    :return:
    """
    form = request.json
    logging.info(json.dumps(form))
    filename = form['name']
    cdn_url = os.getenv("cdnurl", "http://ocm4dfd1v.bkt.clouddn.com")
    if "filename" in form['metaData']:
        url = "%s/%s" % (cdn_url, form['metaData']["filename"])
        name = form['metaData']["filename"]
        file_name = form['metaData']["filename"]
    else:
        url = "%s/%s" % (cdn_url, form['key'])
        name = filename
        file_name = None

    akey = os.getenv("qiniu_ak", "6oIzRgWr30MtIFhpngfaM6vY_9rpe4O9g0zb0KUT")
    skey = os.getenv("qiniu_sk", '4sU23mIWZzvFnHeXwB1uGnYNKZsj7u2KYF0nLEl6')
    bucket = os.getenv("bucket", "mctest")
    token = qiniucloudfile.qiniuuploadfile(akey, skey, bucket, file_name)
    ret_dict = dict()
    ret_dict['token'] = token
    ret_dict['bucket'] = bucket
    ret_dict['provider'] = 'qiniu'
    ret_dict['url'] = url
    ret_dict['upload_url'] = url
    if 'mime_type' in form:
        ret_dict['mime_type'] = form['mime_type']

    logging.debug(ret_dict)
    return jsonify(ret_dict), 200
