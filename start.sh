#!/usr/bin/env bash

gunicorn --worker-class gevent  -w 2 --threads 2 -b 0.0.0.0:5000 src.app.main:app