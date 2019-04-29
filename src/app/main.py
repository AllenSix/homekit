import logging
import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from src.app.config import SQLALCHEMY_DATABASE_URI

logging.basicConfig(format='%(asctime)s %(levelname)s %(module)s.%(funcName)s Line:%(lineno)d %(message)s',
                    level=os.getenv("LOG_LEVEL", 'DEBUG'))
url_prefix = "/1.1"

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True

db = SQLAlchemy(app)

from src.app.user import user
from src.app.group import group
from src.app.busi import busi
from src.app.file import file

app.register_blueprint(user, url_prefix=url_prefix)
app.register_blueprint(file, url_prefix=url_prefix)
app.register_blueprint(group, url_prefix=url_prefix)
app.register_blueprint(busi, url_prefix=url_prefix)


@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers',
                         'X-LC-Session,X-LC-Id,X-LC-Ua,X-LC-Sign,Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response


if __name__ == '__main__':
    app.run(debug=True)
