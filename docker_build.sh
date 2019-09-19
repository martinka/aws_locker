#!/usr/bin/env bash

# specify exact version used for reproducibility
PIP_VERSION=9.0.3

#ARTIFACTORY_PYPI="https://artifactory.programx60.com:443/ssg-generic-local"
trap ': "*** BUILD FAILED ***" $BASH_SOURCE:$LINENO: error: "$BASH_COMMAND" returned $?' ERR
set -eExuo pipefail

# clean
rm -rf build dist

# remove pyc/pyo/__pycache__
find . \( -name \*.pyc -o -name \*.pyo -o -name __pycache__ \) -prune -exec rm -rf {} +

PIPFLAGS=""

# emit relevant version info here
python3 --version
python3 -m pip --version

# install deps
# python3 -m pip --no-cache-dir install --index-url ${ARTIFACTORY_PYPI} -r resouces.txt
python3 -m pip --no-cache-dir install --user -r resources.txt

# compile
python3 -m compileall -f src

# lint
# TODO: Add this back 
# we ignore imports for similarity comparisons
# pylint --disable=duplicate-code,locally-disabled,file-ignored,logging-not-lazy,invalid-name,logging-format-interpolation --reports=n src 

# Add this back
# bandit -lll -r src 

# success
: "*** BUILD SUCCESSFUL ***"
