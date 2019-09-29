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
import subprocess
import collections
import csv
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import Counter

salt_size = 12
sha256_size = 32

credentials_file = "~/.aws/credentials"
encrypted_path = "~/.aws/enc_credentials"

class CorruptedFileError(Exception):
    pass

class DecryptError(Exception):
    pass

def convert_passphrase_to_key(salt, pass_phrase):
    return PBKDF2(pass_phrase, salt, dkLen=32)


def get_cred_file():
    return os.path.expanduser(credentials_file)


def get_enc_cred_file():
    return os.path.expanduser(encrypted_path)

def read_enc_file(pass_phrase):
    # read the file
    filename = get_enc_cred_file()
    with open(filename, 'rb') as f:
        clear_text_hash = f.read(sha256_size)
        enc_text_hash = f.read(sha256_size)
        salt = f.read(salt_size)
        enc_cred_data = f.read()

    # check the file has not been corrupted
    encrypted_hash = SHA256.new()
    encrypted_hash.update( enc_cred_data )
    if encrypted_hash.digest() != enc_text_hash:
       raise CorruptedFileError("encrypted data is corrupted")

    # get the key
    key = convert_passphrase_to_key(salt, pass_phrase)

    # decrypt the data
    ctr = Counter.new(128)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    cred_data = cipher.decrypt(enc_cred_data)

    # check clear text hash to make sure we decrypted correctly
    clear_hash = SHA256.new()
    clear_hash.update( cred_data )
    if clear_hash.digest() != clear_text_hash:
       raise DecryptError("decrypt failed, wrong password?")

    return cred_data

def get_credentials(pass_phrase):
    """
    This function takes a pass_phrase and returns the credentials file as a list
    :param pass_phrase: PassPhrase used to secure the credentials
    :return: The lines of the credentials file as a list
    """
    cred_data = read_enc_file(pass_phrase) 
    cred_lines = cred_data.splitlines()
    return cred_lines

def load_profiles(cred_lines):
    """
     Returns a dictionary of profile_name to dictionary of aws_access_key_id and aws_secret_access_key
    :param cred_lines:
    :return: OrderedDict of profiles
    """
    # load the profiles in the order they appear in the credentials file
    profiles = collections.OrderedDict()
    for line in cred_lines:
        # found new profile
        if b"[" in line and b"]" in line:
            profile_name = line
            profile_name = profile_name.replace(b"[", b"")
            profile_name = profile_name.replace(b"]", b"")
            profile_name = profile_name.strip().decode("utf-8")
            profiles[profile_name] = collections.OrderedDict()
        elif b"aws_access_key_id" in line:
            tokens = line.split(b"=")
            if len(tokens) != 2:
                raise ValueError('aws_secret_access_key entry not well formed, '
                                 'e.g. aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
            # remove any white space
            profiles[profile_name]["aws_access_key_id"] = tokens[1].strip().decode("utf-8")

        elif b"aws_secret_access_key" in line:
            # extract the aws_access_key_id
            tokens = line.split(b"=")
            if len(tokens) != 2:
                raise ValueError('aws_access_key_id entry not well formed, '
                                 'e.g. aws_access_key_id=AKIAIOSFODNN7EXAMPLE')
            profiles[profile_name]["aws_secret_access_key"] = tokens[1].strip().decode("utf-8")

    # if no profiles are loaded perhaps not a valid file or the password was wrong
    if len(profiles) == 0:
        # ask again
        sys.stderr.write("ERROR: Unable to load profiles, please re-enter password." + os.linesep)
        pass_phrase = get_password()
        cred_lines = get_credentials(pass_phrase)
        # convert the list of strings into a dictionary of profiles
        return load_profiles(cred_lines)

    # validate all profiles have correct entries, delete ones without
    for profile in profiles:

        if "aws_access_key_id" not in profiles[profile] or "aws_secret_access_key" not in profiles[profile]:
            print(profiles[profile])
            sys.stderr.write("Profile appears corrupt or password is invalid." + os.linesep)
            raise ValueError("ERROR: failed to load profile: " + profile)

    # return the parsed profiles
    return profiles


def list_profiles(profiles):
    """
    Opens the encrypted credentials file and prints out the names of the profiles, no keys
    :param profiles: Dictionary of profiles
    :return: None
    """
    profile_instance = 0
    print("Available profiles are:")
    for profile in profiles:
        print("[" + str(profile_instance) + "] " + str(profile))
        profile_instance += 1
    print("[" + str(profile_instance) + "] " + "exit")


def activate_keys(profiles, profile):
    """
    Unlocks the credentials file, loads all profiles, prompts the user for profile to choose,
    finds the requested profile, populates the required environment variables.

    :param pass_phrase:  pass phrase used for the encryption key
    :param profile: optional profile name to load
    :return: true to continue false otherwise
    """

    if profile == "":
        list_profiles(profiles)
        selection = None
        while not isinstance(selection, int):
            # prompt the user to select a profile from a list
            selection = get_profile_selection()
            # if the user hits enter we will use the "default" or "first" profile for them
            if selection == "":
                selection = "0"

            try:
                # is their selection a number
                selection = int(selection)
                if len(profiles) < selection or selection < 0:
                    sys.stderr.write("ERROR: Not in the valid range" + os.linesep)
                    # reset their selection
                    selection = ""
                    raise ValueError()
                elif selection == len(profiles):
                    return True
                else:
                    # selected our profile
                    profile = list(profiles)[selection]
                    break
            except ValueError:
                sys.stderr.write("ERROR: please enter a valid selection" + os.linesep)
    else:
        # if the user passed in a specific profile try to use it.
        if profile not in profiles:
            sys.stderr.write("ERROR: " + profile + " was not found" + os.linesep)
            list_profiles(profiles)
            raise ValueError('Unable to find profile named, ' + profile)

    # set the environment variables
    os.environ['AWS_ACCESS_KEY_ID'] = profiles[profile]["aws_access_key_id"]
    os.environ['AWS_SECRET_ACCESS_KEY'] = profiles[profile]["aws_secret_access_key"]
    os.environ['PS1'] = 'aws:' + profile + '> '

    # fork a shell  
    shell = subprocess.Popen(args="/bin/bash",executable='/bin/bash',
                             stdin=sys.stdin, stdout=sys.stdout, 
                             stderr=sys.stderr)
    shell.wait() 
    return False

def encrypt_file(pass_phrase, in_filename, out_filename):
    # read the file
    with open(in_filename, 'rb') as in_file:
        cred_data = in_file.read()

    #generate hash of plain text
    clear_text_hash = SHA256.new()
    clear_text_hash.update( cred_data )

    # get the key
    salt = os.urandom(salt_size)
    key = convert_passphrase_to_key(salt, pass_phrase)

    # encrypt the data
    ctr = Counter.new(128)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    enc_cred_data = cipher.encrypt(cred_data)

    #calculate encrypted hash
    encrypted_hash = SHA256.new()
    encrypted_hash.update( enc_cred_data )
    file_data = clear_text_hash.digest() + encrypted_hash.digest() + salt + enc_cred_data

    # write the file
    with open(out_filename, 'wb') as out_file:
        out_file.write(file_data)

    # remove the unencrypted file
    os.unlink(in_filename)


def decrypt_file(pass_phrase, in_filename, out_filename):
    cred_data = read_enc_file( pass_phrase )
 
    # write the file
    with open(out_filename, 'wb') as out_file:
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


def get_profile_selection():
    """
    This function prompts the user for their profile selection and returns it
    :return: Profile name to use
    """
    profile_number = input("Enter profile number [default]>> ")

    # strip newline of pass_phrase
    return profile_number.rstrip()


def get_password():
    """
    This function prompts the user for their password and returns it to the calling function
    :return: The user's password
    """
    pass_phrase_in = getpass.getpass('enter pass phrase >> ')

    pass_phrase_in = pass_phrase_in.rstrip()

    if pass_phrase_in is "":
        sys.stderr.write("Password cannot be empty, please use a strong pass phrase" + os.linesep)
        return get_password()

    # Return the collected pass phrase
    return pass_phrase_in

def read_csv_file(file_name):
    """
    This function reads an AWS Access key file and returns the keys
    this assumes the file has a header row and then 1 row of keys
    :return dict of key id and secret key
    """
    to_ret = {}
    row_count = 0
    with open( file_name) as csv_cred_file:
        read_csv_cred = csv.reader(csv_cred_file)
        for row in read_csv_cred:
            to_ret['aws_access_key_id'] = row[0]
            to_ret['aws_secret_access_key'] = row[1]    
            row_count += 1
    if row_count != 2:
        sys.stderr.write("could not read credential.csv file")
        exit(-1) 
    return to_ret 

def add_creds( new_creds, profile_name, file_name ):
    with open( file_name, "a") as cred_file:
        cred_file.write('\n[' + profile_name + ']\n')
        cred_file.write('aws_access_key_id=' + new_creds['aws_access_key_id'])
        cred_file.write('\n')
        cred_file.write('aws_secret_access_key=' +
                        new_creds['aws_secret_access_key'] + '\n')

if __name__ == '__main__':
    usage = "Usage: aws_locker [-e,-d,-l,-p profile,-a cred.csv name]" + os.linesep + "" \
            "If no operands are given, a menu will prompt for which profile to use." + os.linesep + "" \
            "The following options are available:" + os.linesep + os.linesep + "" \
            "-h    prints this message" + os.linesep + "" \
            "-e    encrypt the " + credentials_file + " file and write information to " + encrypted_path \
            + os.linesep + "" \
            "-d    decrypt the " + encrypted_path + " file and write information to " + credentials_file \
            + os.linesep + "" \
            "-l    list all profile_names stored in the " + encrypted_path + " file " + os.linesep + "" \
            "-p    activate a specific profile_name from the " + encrypted_path + " file " + os.linesep + "" \
            "-a    add creditials in cred.csv file as profile name " + os.linesep 

    if len(sys.argv) < 1 or len(sys.argv) > 4:
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
    elif num_args == 3 and sys.argv[1] == '-p':
        profile_check()
        profile_name = sys.argv[2]
        print("Attempting to activate " + profile_name)
        pass_phrase = get_password()
        cred_lines = get_credentials(pass_phrase)
        # convert the list of strings into a dictionary of profiles
        profiles = load_profiles(cred_lines)
        # convert the list of strings into a dictionary of profiles
        activate_keys(profiles, profile_name)
        print("Successfully deactivated " + profile_name + " profile" + os.linesep)
    elif num_args == 4 and sys.argv[1] == '-a':
        new_creds = read_csv_file( sys.argv[2] )
        pass_phrase = get_password()
        decrypt_file(get_password(), get_enc_cred_file(), get_cred_file())
        add_creds( new_creds, sys.argv[3], get_cred_file())
        encrypt_file(pass_phrase, get_cred_file(), get_enc_cred_file())
        print("Successfully added keys")
    else:
        print("Attempting to load default profile")
        profile_check()

        # convert the encrypted file to a list of strings
        done = False
        while not done:
            try:
                pass_phrase = get_password()
                cred_lines = get_credentials(pass_phrase)
                done = True
            except DecryptError as de:
                print("Wrong Password try again!")
            except CorruptedFileError as cfe:
                print("encrypted file is corrupt, we can't use it!")
                exit(-1)     

        # convert the list of strings into a dictionary of profiles
        profiles = load_profiles(cred_lines)
        done = False
        while not done:
            done = activate_keys(profiles,"")
            print("Successfully deactivated default profile" + os.linesep)
