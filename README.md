# aws_locker
python program for encrypting local aws access keys while allowing run time access

program allows you to encrypt the ~/.aws/credentials file.

Running on Mac OS:
make sure requirements are loaded:
    pip install -r resources.txt

encrypt the file
    python aws_locker.py -e

enable the access key for working with the command line
    python aws_locker.py 

enable the access key for a non default profile
    python aws_locker.py -p <profile name>

decrypt the file - return the credential file to normal
    python aws_locker.py -d

Running on Windows:
Running on windows is a bit more complicated.
  First step is to ensure python 2.7 is loaded.  By default it is loaded in C:/Python2.7
  Then make sure you have visual C++ compiler for python.  You can get it here: https://www.microsoft.com/en-us/download/details.aspx?id=44266
  Then make sure dependencies are loaded: pip install -r resources.txt.

  after that the commands should work the same as above.


This program makes use of the fact that aws cli will use environment variables for the access key id and access key secret.  The environment variables are not secure, however they are only available while the program is running.  This reduces the exposure of the access keys, however it is not a prefect solution.  It does protect your keys while not in use.  

