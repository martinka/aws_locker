#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR
export LC_ALL=C.UTF-8
export LANG=C.UTF-8 
cd ../..
pipenv run python src/aws_locker.py "$@"
