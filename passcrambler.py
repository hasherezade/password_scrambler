#!/usr/bin/env python
"""
Small utility to generate complicated passwords
For more details refer to https://github.com/hasherezade/password_scrambler
"""
import argparse
import collections
import getpass
import base64
import hashlib
from Crypto.Cipher import AES

###
# AES:

BLOCK_SIZE = 16
PAD = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
DEFAULT_SPECIAL_CHARS = "_&#"
DEFAULT_PASSWORD_LENGTH = 30

###

AESCipherWrapper = collections.namedtuple('AESCipherWrapper', 'seed key')

def encrypt(aes_wrapper, raw):
    """
    encrypts a raw password
    """
    raw = PAD(raw)
    initialization_vector = aes_wrapper.seed[0:AES.block_size]
    cipher = AES.new(aes_wrapper.key, AES.MODE_CBC, initialization_vector)
    return base64.b64encode(initialization_vector + cipher.encrypt(raw))

def scramble(key):
    """
    Scrambles a given key
    :return: scrambled value
    """
    result = hashlib.md5(key).digest()
    return result

###

def get_raw_bytes(filename, offset=0):
    """
    Read and return the bytes from a file
    """
    with open(filename, "rb") as src:
        src.seek(offset, 0)
        data = src.read()
    return data

def convert_to_charset(password, specialchars=DEFAULT_SPECIAL_CHARS):
    """
    converts a password to charset
    :param specialchars: characters used to replace special chars in your password
    """
    assert len(specialchars) >= 3
    is_upper_or_lower_case_char = lambda ch: 'A' <= ch <= 'Z' or 'a' <= ch <= 'z'
    is_digit = lambda ch: '0' <= ch <= '9'

    output = []
    i = 0
    for char in password:
        if is_upper_or_lower_case_char(char) or is_digit(char):
            output.append(char)
            continue
        output.append(specialchars[i])
        i += 1
        if i == len(specialchars):
            i = 0
    return ''.join(output)

def generate_password(args):
    """
    generates a scrambled password
    :param args: parameters used for generating scrambled password
    :return: scrambled password
    """
    aes_out1, key = scramble_and_encrypt(args.password, args.login, args.file)
    aes_out2 = hash_and_encrypt(aes_out1, args.password, key)
    longpass = digest_and_convert(aes_out2, args.length, args.special, key)
    del args
    return longpass


def scramble_and_encrypt(password, login, password_file_name):
    """
    First step in password generation
    """
    key = scramble(password)
    aes = AESCipherWrapper(scramble(login), key)
    aes_out1 = encrypt(aes, get_raw_bytes(password_file_name))
    del aes
    return aes_out1, key

def hash_and_encrypt(aes_from_step1, password, key):
    """
    Second step in password generation
    """
    sha_digest = hashlib.sha512(aes_from_step1).digest()
    passlen = len(password) % len(sha_digest)
    key2 = sha_digest[passlen: passlen + 32]
    aes = AESCipherWrapper(key, key2)
    aes_out2 = encrypt(aes, aes_from_step1)
    del aes
    return aes_out2

def digest_and_convert(aes_from_step2, desired_password_length, special_chars, key):
    """
    Final step in password generation
    """
    start = ord(key[0]) % len(aes_from_step2)
    portion = aes_from_step2[start:]
    result = hashlib.sha512(portion).digest()
    longpass = base64.b64encode(result)
    longpass = longpass[0:desired_password_length]
    longpass = convert_to_charset(longpass, sorted(special_chars, reverse=True))
    return longpass

def read_args():
    """
    read user's input
    """
    parser = argparse.ArgumentParser(description="Password scrambler")
    parser.add_argument('--file', dest="file", default=None,
                        help="File used to initialize generation", required=True)
    parser.add_argument('--login', dest="login", default=None,
                        help="Login for which you want to use the password", required=True)
    parser.add_argument('--special', dest="special", default=DEFAULT_SPECIAL_CHARS,
                        help="Whitelist of special characters, i.e: " + DEFAULT_SPECIAL_CHARS)
    parser.add_argument('--length', dest="length", default=DEFAULT_PASSWORD_LENGTH,
                        help="Length of the password, default=" + str(DEFAULT_PASSWORD_LENGTH),
                        type=int)
    args = parser.parse_args()
    args.password = getpass.getpass()
    return args


def main():
    """
    run the script to generate a long scrambled password
    :return: generated password
    """
    args = read_args()
    print "---\n%s\n---" % generate_password(args)


if __name__ == "__main__":
    main()
