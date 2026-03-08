# !/bin/bash

./build/rocketvault secrets create $1 $2 \
  --tags="prod,dev" \
  --password=sd101 \
  --username=sd101 \
  --totp-code=$3

