#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 18-6-20 上午10:27
# @Author  : Skye
# @Site    : 
# @File    : mail.py
# @Software: PyCharm

import smtplib
from email.header import Header
from email.mime.text import MIMEText

from src.app.config import *


def send_email(title, content, receivers):
    message = MIMEText(content, 'plain', 'utf-8')  # 内容, 格式, 编码
    message['From'] = "{}".format(MAIL_SENDER)
    message['To'] = receivers
    message['Subject'] = title

    try:
        # smtpObj = smtplib.SMTP_SSL(MAIL_HOST, 465)  # 启用SSL发信, 端口一般是465
        smtpObj = smtplib.SMTP(MAIL_HOST, 587)  # 启用SSL发信, 端口一般是465
        smtpObj.ehlo()
        smtpObj.starttls()
        smtpObj.login(MAIL_USER, MAIL_PASS)  # 登录验证
        smtpObj.sendmail(MAIL_SENDER, receivers, message.as_string())  # 发送
        print("mail has been send successfully.")
    except smtplib.SMTPException as e:
        print(e)
