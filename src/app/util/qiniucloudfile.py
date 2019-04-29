# coding=utf-8
'''
Created on Aug 28, 2016

@author: aadebuger
'''
import logging
import qiniu

import os

access_key = '6oIzRgWr30MtIFhpngfaM6vY_9rpe4O9g0zb0KUT'
secret_key = '4sU23mIWZzvFnHeXwB1uGnYNKZsj7u2KYF0nLEl6'
bucket_name = "mctest"


def get_bin_file(filename):
    '''
    no use
    Get the all content of the binary file.
    
    input: filename - the binary file name
    return: binary string - the content of the file. 
    '''

    if not os.path.isfile(filename):
        print("ERROR: %s is not a valid file." % (filename))
        return None

    f = open(filename, "rb")
    data = f.read()
    f.close()

    return data


def uploadfile(key, data):
    """
    上传数据文件到qiniu
    :param key:
    :param data:
    :return:
    """
    q = qiniu.Auth(access_key, secret_key)
    token = q.upload_token(bucket_name)
    ret, info = qiniu.put_data(token, key, data)
    if ret is not None:
        return ret
    else:
        print(info)


def tokenuploadfile(token, key, data):
    """
    no use
    :param token:
    :param key:
    :param data:
    :return:
    """
    ret, info = qiniu.put_data(token, key, data)
    if ret is not None:
        return ret
    else:
        print(info)  #


def qiniuuploadfile(access_key1, secret_key1, bucket_name1, key=None):
    """
    获取qiniu 上传token
    :param key: 
    :param access_key1:
    :param secret_key1:
    :param bucket_name1:
    :return:
    """
    q = qiniu.Auth(access_key1, secret_key1)
    token = q.upload_token(bucket_name1, key)
    logging.info("qiniu token：" + token)
    return token


if __name__ == '__main__':
    pass
