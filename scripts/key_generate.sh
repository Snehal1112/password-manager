# !/bin/bash

echo $1
# This script generates a new SSH key pair and adds the public key to the ssh-agent.
# ./build/rocketvault keys generate \
#   --type=rsa \
#   --name=secret-key \
#   --bits=2048 \
#   --curve=p256 \
#   --tags="prod,dev" \
#   --password=sd101 \
#   --username=sd101 \
#   --totp-code= $1 \

# ./build/rocketvault secrets create "secret-key" "sd" \
#   --tags="prod,dev" \
#   --password=sd101 \
#   --username=sd101 \
#   --totp-code=$1

./build/rocketvault secrets list \
  --tags="prod,dev" \
  --password=sd101 \
  --username=sd101 \
  --totp-code=$1