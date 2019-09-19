#!/bin/bash

trap ': "*** BUILD FAILED ***" $BASH_SOURCE:$LINENO: error: "$BASH_COMMAND" returned $?' ERR
set -eExuo pipefail

export LC_ALL=C.UTF-8
export LANG=C.UTF-8 

# change into the directory that contains the script 
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $DIR

cd src

# run tests 
pipenv run python -m unittest test_aws_locker

# TODO run linter

# TODO create a pyinstaller executable for MacOS
# TODO create a pyinstaller executable for Windows
