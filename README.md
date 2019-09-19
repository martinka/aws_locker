# aws_locker
python program for encrypting local aws access keys while allowing run time access

program allows you to encrypt the ~/.aws/credentials file.

Before you Start:
=================
It is always a good idea to backup you aws credentials someplace off line. This program will encrypt you credentials. If you forget the pass key there is no way to recover them.

Running on Mac OS:
==================
make sure requirements are loaded:
```
    pip install -r resources.txt
```

encrypt the file
```
    python aws_locker.py -e
```

enable the access key for working with the command line
```
    python aws_locker.py
```

enable the access key for a non default profile
```
    python aws_locker.py -p <profile name>
```

decrypt the file - return the credential file to normal
```
    python aws_locker.py -d
```

Running on Windows:
===================
Running on windows is a bit more complicated.
  First step is to ensure python 2.7 is loaded.  By default it is loaded in C:/Python2.7
  Then make sure you have visual C++ compiler for python.  You can get it here: https://www.microsoft.com/en-us/download/details.aspx?id=44266
  Then make sure dependencies are loaded: pip install -r resources.txt.

  after that the commands should work the same as above.


This program makes use of the fact that aws cli will use environment variables for the access key id and access key secret.  The environment variables are not secure, however they are only available while the program is running.  This reduces the exposure of the access keys, however it is not a prefect solution.  It does protect your keys while not in use.  

Running a docker container:
===========================
Install docker on your computer:
* MacOS https://runnable.com/docker/install-docker-on-macos
* Windows 10 https://runnable.com/docker/install-docker-on-windows-10
* Linux https://runnable.com/docker/install-docker-on-linux

Execute the build script
```
./build.sh
```

To run the container, execute the run script and follow the aws_locker prompts
NOTE: if you already have a encrypted file in your ~/.aws directory it will be loaded 
```
./run.sh
```



Acknowledgements
================
Thank you to [darbym](https://github.com/darbym), [adbrowning](https://github.com/adbrowning) and [rmuir](https://github.com/rmuir) for inspirtation and initial code review.


Future Plans
============
The following enchancements are planed for aws_locker
  - unit tests
  - builds for .app and .exe versions
