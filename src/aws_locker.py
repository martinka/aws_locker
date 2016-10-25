"""
aws_locker is a utility to allow you to keep your aws access keys encrypted, and only decrypt them when you are running.

Copyright (c) 2016 Michael E. Martinka

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import os
import sys
import getpass
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util import Counter

salt_size = 12


def convert_passphrase_to_key(salt, pass_phrase):
    return PBKDF2(pass_phrase, salt, dkLen=32)


def get_cred_file():
    return os.path.expanduser("~/.aws/credentials")


def get_enc_cred_file():
    return os.path.expanduser("~/.aws/enc_credentials")


def activate_keys(pass_phrase, profile):
    # read the file
    filename = get_enc_cred_file()
    with open(filename, 'r') as f:
        salt = f.read(salt_size)
        enc_cred_data = f.read()

    # get the key
    key = convert_passphrase_to_key(salt, pass_phrase)

    # decrypt the data
    ctr = Counter.new(128)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    cred_data = cipher.decrypt(enc_cred_data)
    cred_lines = cred_data.splitlines()

    # find the start of the profile
    profile_idx = 0
    while profile not in cred_lines[profile_idx] and profile_idx < len(cred_lines):
        profile_idx += 1

    if profile_idx >= len(cred_lines):
        raise ValueError('profile not found')

    # find the aws access key
    access_key_idx = profile_idx
    while 'aws_access_key_id =' not in cred_lines[access_key_idx] and access_key_idx < len(cred_lines):
        access_key_idx += 1

    if access_key_idx >= len(cred_lines):
        raise ValueError('aws_access_key_id not found')

    # find the aws secret key
    secret_key_idx = profile_idx
    while 'aws_secret_access_key =' not in cred_lines[secret_key_idx] and secret_key_idx < len(cred_lines):
        secret_key_idx += 1

    if secret_key_idx >= len(cred_lines):
        raise ValueError('aws_secret_acces_key not found')

    # extract the values
    start = len('aws_access_key_id =') + 1
    access_key = cred_lines[access_key_idx][start:]

    start = len('aws_secret_access_key =') + 1
    secret_key = cred_lines[secret_key_idx][start:]

    # set the environment variables
    os.environ['AWS_ACCESS_KEY_ID'] = access_key
    os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key

    # main command line loop
    cmd = ""
    while cmd != 'exit':
        sys.stdout.write('>')
        cmd = sys.stdin.readline()
        # strip newline off cmd
        cmd = cmd.strip()
        if cmd != 'exit':
            os.system(cmd)


def encrypt_file(pass_phrase, in_filename, out_filename):
    # read the file
    with open(in_filename, 'r') as in_file:
        cred_data = in_file.read()

    # get the key
    salt = os.urandom(salt_size)
    key = convert_passphrase_to_key(salt, pass_phrase)

    # encrypt the data
    ctr = Counter.new(128)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    enc_cred_data = cipher.encrypt(cred_data)
    file_data = salt + enc_cred_data

    # write the file
    with open(out_filename, 'w') as out_file:
        out_file.write(file_data)

    # remove the unencrypted file
    os.unlink(in_filename)


def decrypt_file(pass_phrase, in_filename, out_filename):
    # read the file
    with open(in_filename, 'r') as in_file:
        salt = in_file.read(salt_size)
        enc_cred_data = in_file.read()

    # get the key
    key = convert_passphrase_to_key(salt, pass_phrase)

    # decrypt the data
    ctr = Counter.new(128)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    cred_data = cipher.decrypt(enc_cred_data)

    # write the file
    with open(out_filename, 'w') as out_file:
        out_file.write(cred_data)

    # remove encrypted file
    os.unlink(in_filename)


if __name__ == '__main__':
    if len(sys.argv) < 1 or len(sys.argv) > 3:
        print("usage: aws_locker [-e,-d,-p profile]")
        exit()
    pass_phrase_in = getpass.getpass('enter pass phrase>')

    # strip newline of pass_phrase
    pass_phrase_in = pass_phrase_in.rstrip()

    if len(sys.argv) == 2 and sys.argv[1] == '-e':
        print("encrypting the cred file\n")
        encrypt_file(pass_phrase_in, get_cred_file(), get_enc_cred_file())
    elif len(sys.argv) == 2 and sys.argv[1] == '-d':
        print("decrypting the cred file\n")
        decrypt_file(pass_phrase_in, get_enc_cred_file(), get_cred_file())
    elif len(sys.argv) == 3 and sys.argv[1] == '-p':
        print("activating profile")
        activate_keys(pass_phrase_in, sys.argv[2])
    else:
        print("activating default profile\n")
        activate_keys(pass_phrase_in, "default")
