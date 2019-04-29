FROM python:3.6

RUN pip install flask -i https://mirrors.aliyun.com/pypi/simple/
RUN pip install flask-cors -i https://mirrors.aliyun.com/pypi/simple/
RUN pip install gunicorn gevent  -i https://mirrors.aliyun.com/pypi/simple/
RUN pip install passlib -i https://mirrors.aliyun.com/pypi/simple/
RUN pip install PyJWT  -i https://mirrors.aliyun.com/pypi/simple/
RUN pip install qiniu -i https://mirrors.aliyun.com/pypi/simple/
RUN pip install flask-restful -i https://mirrors.aliyun.com/pypi/simple/
RUN pip install iso8601 -i https://mirrors.aliyun.com/pypi/simple/
RUN pip install rx -i https://mirrors.aliyun.com/pypi/simple/
RUN pip install PyMySQL -i https://mirrors.aliyun.com/pypi/simple/
RUN pip install DBUtils -i https://mirrors.aliyun.com/pypi/simple/
RUN pip install Flask-SQLAlchemy -i https://mirrors.aliyun.com/pypi/simple/
RUN pip install mysqlclient  -i https://mirrors.aliyun.com/pypi/simple/

ADD src/ /code/src
ADD start.sh /code
WORKDIR /code
CMD ["sh","start.sh"]
