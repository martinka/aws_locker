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

credentials_file = "~/.aws/credentials"
encrypted_path = "~/.aws/enc_credentials"


def convert_passphrase_to_key(salt, pass_phrase):
    return PBKDF2(pass_phrase, salt, dkLen=32)


def get_cred_file():
    return os.path.expanduser(credentials_file)


def get_enc_cred_file():
    return os.path.expanduser(encrypted_path)


def get_credentials(pass_phrase):
    """
    This function takes a pass_phrase and returns the credentials file as a list
    :param pass_phrase: PassPhrase used to secure the credentials
    :return: The lines of the credentials file as a list
    """
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
    return cred_lines


def list_profiles(pass_phrase):
    """
    Opens the encrypted credentials file and prints out the names of the profiles, no keys
    :param pass_phrase: PassPhrase used to secure the credentials
    :return: None
    """
    cred_lines = get_credentials(pass_phrase)
    for line in cred_lines:
        if "[" in line and "]" in line:
            print(line)


def activate_keys(pass_phrase, profile):
    cred_lines = get_credentials(pass_phrase)

    # find the start of the profile
    profile_idx = 0
    while profile not in cred_lines[profile_idx] and profile_idx < len(cred_lines):
        profile_idx += 1

    if profile_idx >= len(cred_lines):
        raise ValueError('profile not found')

    # find the aws access key
    access_key_idx = profile_idx
    while 'aws_access_key_id' not in cred_lines[access_key_idx] and access_key_idx < len(cred_lines):
        access_key_idx += 1

    if access_key_idx >= len(cred_lines):
        raise ValueError('aws_access_key_id not found')

    # find the aws secret key
    secret_key_idx = profile_idx
    while 'aws_secret_access_key' not in cred_lines[secret_key_idx] and secret_key_idx < len(cred_lines):
        secret_key_idx += 1

    if secret_key_idx >= len(cred_lines):
        raise ValueError('aws_secret_acces_key not found')

    # extract the aws_access_key_id
    tokens = cred_lines[access_key_idx].split("=")
    if len(tokens) != 2:
        raise ValueError('aws_access_key_id entry not well formed, '
                         'e.g. aws_access_key_id=AKIAIOSFODNN7EXAMPLE')
    # remove any white space
    access_key = tokens[1].strip()
    
    # extract the aws_secret_access_key
    tokens = cred_lines[secret_key_idx].split("=")
    if len(tokens) != 2:
        raise ValueError('aws_secret_access_key entry not well formed, '
                         'e.g. aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
    # remove any white space
    secret_key = tokens[1].strip()
    
    # set the environment variables
    os.environ['AWS_ACCESS_KEY_ID'] = access_key
    os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key

    # main command line loop
    cmd = ""
    while cmd != 'exit':
        sys.stdout.write('> ')
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


def profile_check():
    """
    This function checks whether the encrypted credential file exists or not and then exits if missing
    :return:
    """
    # default profile
    if not os.path.exists(get_enc_cred_file()):
        sys.stderr.write("Encrypted credential file not found, create an encrypted file" + os.linesep)
        sys.stderr.write(usage)
        exit()


def get_password():
    """
    This function prompts the user for their password and returns it to the calling function
    :return: The user's password
    """
    pass_phrase_in = getpass.getpass('enter pass phrase >>')

    # strip newline of pass_phrase
    return pass_phrase_in.rstrip()


if __name__ == '__main__':
    usage = "Usage: aws_locker [-e,-d,-l,-p profile]" + os.linesep + "" \
            "If no operands are given, the \"default\" profile credentials are loaded.  " + os.linesep + "" \
            "The following options are available:" + os.linesep + os.linesep + "" \
            "-h    prints this message" + os.linesep + "" \
            "-e    encrypt the " + credentials_file + " file and write information to " + encrypted_path \
            + os.linesep + "" \
            "-d    decrypt the " + encrypted_path + " file and write information to " + credentials_file \
            + os.linesep + "" \
            "-l    list all profile_names stored in the " + encrypted_path + " file " + os.linesep + "" \
            "-p    activate a specific profile_name from the " + encrypted_path + " file " + os.linesep

    if len(sys.argv) < 1 or len(sys.argv) > 3:
        sys.stderr.write(usage)
        exit()

    num_args = len(sys.argv)

    if num_args == 2 and sys.argv[1] == '-e':
        encrypt_file(get_password(), get_cred_file(), get_enc_cred_file())
        print("credentials file encrypted" + os.linesep)
    elif num_args == 2 and sys.argv[1] == '-h':
        sys.stdout.write(usage)
        sys.exit(0)
    elif num_args == 2 and sys.argv[1] == '-d':
        profile_check()
        decrypt_file(get_password(), get_enc_cred_file(), get_cred_file())
        print("credentials file decrypted" + os.linesep)
    elif num_args == 2 and sys.argv[1] == '-l':
        profile_check()
        list_profiles(get_password())

    elif num_args == 3 and sys.argv[1] == '-p':
        profile_check()
        profile_name = sys.argv[2]
        print("Attempting to activate " + profile_name)
        activate_keys(get_password(), profile_name)
        print("Successfully deactivated " + profile_name + " profile" + os.linesep)
    else:
        print("Attempting to load default profile")
        profile_check()
        activate_keys(get_password(), "default")
        print("Successfully deactivated default profile" + os.linesep)
