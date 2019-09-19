#!/bin/bash
# This script builds the docker container

# check docker is available
if ! type "docker"; then
  cat << EOL
You need docker installed.
Please follow installation instructions from: https://docs.docker.com/install/
EOL
  exit 1
fi

docker build -t aws_locker:latest .
echo "Build successful please execute the ./run.sh script to launch the image"
