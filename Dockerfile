# docker hub local remote
FROM ubuntu:18.04

# Dockerfile metadata
LABEL version="1.0"
LABEL description="Dockerfile base for AWS Locker"

# docker hardcoded sh...
SHELL ["/bin/bash", "-c"]

RUN apt-get update --fix-missing
# Install utilities
RUN apt-get install -y net-tools sudo build-essential software-properties-common

# Install libraries required by aws-cli
RUN apt-get install -y less groff

RUN add-apt-repository ppa:deadsnakes/ppa
RUN apt-get update

# install python
RUN apt-get install -y python-setuptools python3-pip python3.7 python3-dev python-dev

# install vim 
RUN apt-get install -y vim 

# ensure pip is upgraded
RUN pip3 install --upgrade pip

# install pipenv 
RUN pip install pipenv

# cleanup image
RUN apt-get -y clean && \
    apt-get -y autoremove

ENV SRC_DIR=$HOME/aws_locker
# copy this repo into container
COPY . $SRC_DIR/.

# setup virtualenv
RUN cd $SRC_DIR && \
    export LC_ALL=C.UTF-8 && \
    export LANG=C.UTF-8 && \
    export PATH=$PATH:/root/.local/bin && \
    mkdir $HOME/.pip && \
    pipenv install --python 3.7 -r resources.txt && \
    ./docker_build.sh
