#!/usr/bin/env bash

docker build -t homekit/api .
docker tag homekit/api csf71106410/homekit_api
docker push csf71106410/homekit_api