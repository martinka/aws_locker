#!/bin/bash

trap ': "*** BUILD FAILED ***" $BASH_SOURCE:$LINENO: error: "$BASH_COMMAND" returned $?' ERR
set -eExuo pipefail

cd src

# run tests 
pipenv run python -m unittest test_aws_locker

# TODO run linter

# TODO create a pyinstaller executable for MacOS
# TODO create a pyinstaller executable for Windows
