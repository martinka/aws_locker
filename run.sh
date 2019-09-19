#!/bin/bash

# Launch the container 
# Mount the local .aws directory into root's ~/.aws directory
# run the aws_locker.sh script with the arguments passed to this script
# Delete it after use
docker run -v ~/.aws:/root/.aws --rm -it aws_locker:latest /aws_locker/src/scripts/aws_locker.sh "$@"
