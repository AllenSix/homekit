import os

# SQLALCHEMY_DATABASE_URI = os.getenv("SQLALCHEMY_DATABASE_URI", 'mysql://root:831227@localhost/homekit')
SQLALCHEMY_DATABASE_URI = os.getenv("SQLALCHEMY_DATABASE_URI", 'mysql://root:nlhomekit@10.3.131.107/homekit')

MAIL_HOST = os.getenv("MAIL_HOST", "smtp.exmail.qq.com")  # SMTP服务器
MAIL_USER = os.getenv("MAIL_USER", "zhengxiaohua@shgs989.com")  # 用户名
MAIL_PASS = os.getenv("MAIL_PASS", "dekMJyEq3rczVFed")  # 授权密码，非登录密码
MAIL_SENDER = os.getenv("MAIL_SENDER", "zhengxiaohua@shgs989.com")

APP_SECRET = os.getenv("APP_SECRET", "All the world's a stage")
