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
        if "[" in line and "]" in line:
            profile_name = line
            profile_name = profile_name.replace("[", "")
            profile_name = profile_name.replace("]", "")
            profile_name = profile_name.strip()
            profiles[profile_name] = collections.OrderedDict()
        elif "aws_access_key_id" in line:
            tokens = line.split("=")
            if len(tokens) != 2:
                raise ValueError('aws_secret_access_key entry not well formed, '
                                 'e.g. aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
            # remove any white space
            profiles[profile_name]["aws_secret_access_key"] = tokens[1].strip()

        elif "aws_access_key_id" in line:
            # extract the aws_access_key_id
            tokens = line.split("=")
            if len(tokens) != 2:
                raise ValueError('aws_access_key_id entry not well formed, '
                                 'e.g. aws_access_key_id=AKIAIOSFODNN7EXAMPLE')
            profiles[profile_name]["aws_secret_access_key"] = tokens[1].strip()

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

        if "aws_access_key_id" not in profiles[profile] and "aws_secret_access_key" not in profiles[profile]:
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
        print("[" + str(profile_instance) + "] " + profile)
        profile_instance += 1


def activate_keys(pass_phrase, profile):
    """
    Unlocks the credentials file, loads all profiles, prompts the user for profile to choose,
    finds the requested profile, populates the required environment variables.

    :param pass_phrase:  pass phrase used for the encryption key
    :param profile: optional profile name to load
    :return:
    """
    # convert the encrypted file to a list of strings
    cred_lines = get_credentials(pass_phrase)
    # convert the list of strings into a dictionary of profiles
    profiles = load_profiles(cred_lines)

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
                if len(profiles) <= selection or selection < 0:
                    sys.stderr.write("ERROR: Not in the valid range" + os.linesep)
                    # reset their selection
                    selection = ""
                    raise ValueError()
                else:
                    # selected our profile
                    profile = profiles.keys()[selection]
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
    os.environ['AWS_ACCESS_KEY_ID'] = profiles[profile]["aws_secret_access_key"]
    os.environ['AWS_SECRET_ACCESS_KEY'] = profiles[profile]["aws_secret_access_key"]
    os.environ['PS1'] = 'aws:' + profile + '> '

    # fork a shell  
    shell = subprocess.Popen(args="/bin/bash",executable='/bin/bash',
                             stdin=sys.stdin, stdout=sys.stdout, 
                             stderr=sys.stderr)
    shell.wait() 


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


def get_profile_selection():
    """
    This function prompts the user for their profile selection and returns it
    :return: Profile name to use
    """
    profile_number = raw_input("Enter profile number [default]>> ")

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


if __name__ == '__main__':
    usage = "Usage: aws_locker [-e,-d,-l,-p profile]" + os.linesep + "" \
            "If no operands are given, a menu will prompt for which profile to use." + os.linesep + "" \
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
    elif num_args == 3 and sys.argv[1] == '-p':
        profile_check()
        profile_name = sys.argv[2]
        print("Attempting to activate " + profile_name)
        activate_keys(get_password(), profile_name)
        print("Successfully deactivated " + profile_name + " profile" + os.linesep)
    else:
        print("Attempting to load default profile")
        profile_check()
        activate_keys(get_password(), "")
        print("Successfully deactivated default profile" + os.linesep)
