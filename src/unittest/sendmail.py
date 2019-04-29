#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 18-6-20 上午9:58
# @Author  : Skye
# @Site    : 
# @File    : sendmail.py
# @Software: PyCharm

import smtplib
from email.header import Header
from email.mime.text import MIMEText

# 第三方 SMTP 服务
mail_host = "smtp-mail.outlook.com"  # SMTP服务器
mail_user = "Sundries_app@outlook.com"  # 用户名
mail_pass = "19871024Mrf"  # 授权密码，非登录密码

sender = "Sundries_app@outlook.com"
receivers = "zxh@zqf.com.cn"

content = '验证码1234'
title = '验证码邮件'  # 邮件主题


def sendEmail():
    message = MIMEText(content, 'plain', 'utf-8')  # 内容, 格式, 编码
    message['From'] = "{}".format(sender)
    message['To'] = receivers
    message['Subject'] = title

    try:
        smtpObj = smtplib.SMTP(mail_host, 587)  # 启用SSL发信, 端口一般是465
        smtpObj.ehlo()
        smtpObj.starttls()
        smtpObj.login(mail_user, mail_pass)  # 登录验证
        smtpObj.sendmail(sender, receivers, message.as_string())  # 发送
        print("mail has been send successfully.")
    except smtplib.SMTPException as e:
        print(e)


def send_email2(SMTP_host, from_account, from_passwd, to_account, subject, content):
    email_client = smtplib.SMTP(SMTP_host)
    email_client.login(from_account, from_passwd)
    # create msg
    msg = MIMEText(content, 'plain', 'utf-8')
    msg['Subject'] = Header(subject, 'utf-8')  # subject
    msg['From'] = from_account
    msg['To'] = to_account
    email_client.sendmail(from_account, to_account, msg.as_string())

    email_client.quit()


if __name__ == '__main__':
    sendEmail()
