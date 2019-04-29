"""
@version: ??
@author: zhengxh
@license: Apache Licence 
@file: util.py
@time: 17-9-15 上午9:14

工具
"""

import hashlib
import json
import logging
import os
import random

from datetime import datetime, timedelta
import time

import re

from flask import request
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, SignatureExpired, BadSignature)

SECRET_KEY = 'i love chengdu chunxilu yeah'


def get_remote_ip():
    """
    获取登陆IP
    :return:
    """
    forwarded_ip = request.headers.get("X-Forwarded-For")
    if forwarded_ip is not None:
        return forwarded_ip.split(",")[0]
    else:
        return request.remote_addr


def is_phone(phone):
    """
    判断是否手机号码
    :param phone:
    :return:
    """
    pattern = re.compile(r'^1\d{10}$')
    if pattern.match(phone) is not None:
        return True
    return False


def mask_phone(phone):
    """
    对手机号码中间4位做覆盖处理
    :param phone:
    :return:
    """
    pattern = re.compile(r'^1\d{10}$')
    if pattern.match(phone) is not None:
        return phone[0:3] + "****" + phone[7:]
    return phone


def get_md5(src=""):
    """
    获取md5
    :param src:
    :return:
    """
    m2 = hashlib.md5()
    m2.update(src.encode("utf8"))
    return m2.hexdigest()


def get_op_id():
    """
    获取操作ID
    :return:
    """
    return int(round(time.time() * 1000))


def get_iso8601():
    """
    获取iso8601格式的当前时间
    :return:
    """
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + "Z"


def get_mysql_datetime_from_iso(iso8601_date=""):
    """
    获取iso8601格式的当前时间
    :return:
    """
    return iso8601_date.replace("T", " ").replace("Z", "")


def get_iso8601_from_dt(dt):
    """
    获取iso8601格式的时间
    :param dt:
    :return:
    """
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + "Z"


def transfer_iso_datetime(date_iso):
    """
    把iso日期转换为datetime
    :param date_iso:
    :return:
    """
    return datetime.strptime(date_iso, "%Y-%m-%dT%H:%M:%S.%fZ") + timedelta(hours=8)


def get_db_ip():
    """
    获取数据库链接IP
    :return:
    返回数据库连接IP
    """
    return os.environ.get('MYDB_PORT_27017_TCP_ADDR', "127.0.0.1")


def __uniqueid__():
    """
      generate unique id with length 17 to 21.
      ensure uniqueness even with daylight savings events (clocks adjusted one-hour backward).

      if you generate 1 million ids per second during 100 years, you will generate
      2*25 (approx sec per year) * 10**6 (1 million id per sec) * 100 (years) = 5 * 10**9 unique ids.

      with 17 digits (radix 16) id, you can represent 16**17 = 295147905179352825856 ids (around 2.9 * 10**20).
      In fact, as we need far less than that, we agree that the format used to represent id (seed + timestamp reversed)
      do not cover all numbers that could be represented with 35 digits (radix 16).

      if you generate 1 million id per second with this algorithm, it will increase the seed by less than 2**12 per
      hour so if a DST occurs and backward one hour, we need to ensure to generate unique id for twice times for the
      same period. the seed must be at least 1 to 2**13 range. if we want to ensure uniqueness for two hours (100%
      contingency), we need a seed for 1 to 2**14 range. that's what we have with this algorithm. You have to
      increment seed_range_bits if you move your machine by airplane to another time zone or if you have a glucky
      wallet and use a computer that can generate more than 1 million ids per second.

      one word about predictability : This algorithm is absolutely NOT designed to generate unpredictable unique id.
      you can add a sha-1 or sha-256 digest step at the end of this algorithm but you will loose uniqueness and enter
      to collision probability world. hash algorithms ensure that for same id generated here, you will have the same
      hash but for two differents id (a pair of ids), it is possible to have the same hash with a very little
      probability. You would certainly take an option on a bijective function that maps 35 digits (or more) number to
      35 digits (or more) number based on cipher block and secret key. read paper on breaking PRNG algorithms in
      order to be convinced that problems could occur as soon as you use random library :)

      1 million id per second ?... on a Intel(R) Core(TM)2 CPU 6400 @ 2.13GHz, you get :

      >>> timeit.timeit(uniqueid,number=40000)
      1.0114529132843018

      an average of 40000 id/second
    """
    mynow = datetime.now
    sft = datetime.strftime
    # store old datetime each time in order to check if we generate during same microsecond (glucky wallet !)
    # or if daylight savings event occurs (when clocks are adjusted backward) [rarely detected at this level]
    old_time = mynow()  # fake init - on very speed machine it could increase your seed to seed + 1... but we have
    # our contingency :)
    # manage seed
    seed_range_bits = 14  # max range for seed
    seed_max_value = 2 ** seed_range_bits - 1  # seed could not exceed 2**nbbits - 1
    # get random seed
    seed = random.getrandbits(seed_range_bits)
    current_seed = str(seed)
    # producing new ids
    while True:
        # get current time
        current_time = mynow()
        if current_time <= old_time:
            # previous id generated in the same microsecond or Daylight saving time event occurs (when clocks are
            # adjusted backward)
            seed = max(1, (seed + 1) % seed_max_value)
            current_seed = str(seed)
        # generate new id (concatenate seed and timestamp as numbers)
        # newid=hex(int(''.join([sft(current_time,'%f%S%M%H%d%m%Y'),current_seed])))[2:-1]
        newid = int(''.join([sft(current_time, '%f%S%M%H%d%m%Y'), current_seed]))
        # save current time
        old_time = current_time
        # return a new id
        yield newid


def generate_auth_token(secret_key, user_id, expiration=3600000):
    """
    使用itsdangerous 生成token
    :param user_id:
    :param secret_key:
    :param expiration:
    :return:
    """
    s = Serializer(secret_key, expires_in=expiration)
    return s.dumps(str(user_id))


def review_auth_token(secret_key, token):
    """
    使用itsdangerous 还原用户信息
    :return:
    """
    s = Serializer(secret_key)
    try:
        data = s.loads(token)
    except SignatureExpired as e:
        data = e.payload
    except BadSignature:
        return None  # invalid token
    return data


def parse_get_where_params():
    """
    获取前端get where参数,包括ios，安卓和curl，统一返回dict
    :return:
    None or dict
    """
    ret = dict()
    where = request.args.get("where", None)
    if where in (None, ""):
        return None
    # logging.info(where)
    where = json.loads(where)
    # 兼容ios
    if "$and" in where:
        if type(where["$and"]) == list:
            for i in where["$and"]:
                for (k, v) in i.items():
                    ret[k] = v
        elif type(where["$and"]) == dict:
            for (k, v) in where["$and"].items():
                ret[k] = v
        else:
            logging.debug(where)
    else:
        for (k, v) in where.items():
            ret[k] = v
    return ret


def to_dict(self):
    return {c.name: getattr(self, c.name, None) for c in self.__table__.columns}


if __name__ == '__main__':
    pass
