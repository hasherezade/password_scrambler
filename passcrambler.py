#!/usr/bin/env python

from __future__ import unicode_literals
from __future__ import print_function

from builtins import bytes

import sys
import os
import argparse
import getpass
import base64
import hashlib

from itertools import cycle

from Crypto.Cipher import AES

###
# AES:

BLOCK_SIZE = 16
pad = lambda s: s + ((BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)).encode()

class AESCipher:
    def __init__( self, seed, key ):
        self.key = key
        self.seed = seed

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = self.seed[0:AES.block_size]
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) ) 
###

def scramble(key):
    result = hashlib.md5(key.encode()).digest()
    return bytes(result)

###

def get_raw_bytes(filename, offset=0):
    fo = open(filename,"rb")
    fo.seek(offset, 0)
    data = fo.read()
    fo.close()
    return data

def convert_to_charset(password, specialchars, must_include):
    output = ""
    specialchars_iterator = cycle(sorted(specialchars))
    must_include_iterator = iter(sorted(must_include))
    for i, c in enumerate(password):
        if i % 2 and must_include:
            try:
                output += next(must_include_iterator)
            except StopIteration:
                pass

        if c.isalnum():
            output += c
            continue
        try:
            output += next(specialchars_iterator)
        except StopIteration:
            pass
    return output        
   
def main():
    parser = argparse.ArgumentParser(description="Password scrambler")
    parser.add_argument('--file', dest="file", default=None, help="File used to initialize generation", required=True)
    parser.add_argument('--login', dest="login", default=None, help="Login for which you want to use the password", required=True)
    parser.add_argument('--special', dest="special", default="_&#", help="Whitelist of special characters, i.e: '_&#'")
    parser.add_argument('--must-include',
                        dest="must_include",
                        default="",
                        help="A list of characters that must be included in the generated password")
    parser.add_argument('--length', dest="length", default=30, help="Length of the password, default=30", type=int)
    args = parser.parse_args()

    password = getpass.getpass()
    key = scramble(password)    
    vec = scramble(args.login)

    raw = get_raw_bytes(args.file)
    aes = AESCipher(vec, key)
    aes_out1 = aes.encrypt(raw)
    del aes

    sha_digest = hashlib.sha512(aes_out1).digest()
    passlen = len(password) % len(sha_digest)
    key2 = sha_digest[passlen: passlen+32]
    aes = AESCipher(key, key2)
    aes_out2 = aes.encrypt(aes_out1)
    del aes
    
    start = key[0] % len(aes_out2)
    portion = aes_out2[start:]
    result = hashlib.sha512(portion).digest()
    longpass = base64.b64encode(result)
    longpass = longpass[0:args.length]
    longpass = convert_to_charset(longpass.decode(), args.special, args.must_include)
    longpass = longpass[0:args.length]
    print("---")
    print(longpass)
    print("---")

if __name__ == "__main__":
    main()

