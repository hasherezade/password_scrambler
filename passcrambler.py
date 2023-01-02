#!/usr/bin/env python3

import argparse
import getpass
import base64
import hashlib
import pyperclip
from Crypto.Cipher import AES

# AES:
pad = lambda s: s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size).encode()


def aes_encrypt(seed, key, raw):
    raw = pad(raw)
    iv = seed[0:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


def scramble(key, func='md5'):
    try:
        # AES key must be either 16, 24, or 32 bytes long
        proper_key = len(eval('hashlib.%s(key).digest()' % func))
        if proper_key >= 32:
            return eval('hashlib.%s(key).digest()[:32]' % func)
        elif 24 <= proper_key < 32:
            return eval('hashlib.%s(key).digest()[:24]' % func)
        elif 16 <= proper_key < 24:
            return eval('hashlib.%s(key).digest()[:16]' % func)
        else:
            print(f"[ERROR]: Key length {proper_key} is to small. Please select a different hash function.")
    except Exception as e:
        print(f"[ERROR]: {e}")


def convert_to_charset(password, specialchars):
    output = ""
    i = 0
    slen = len(specialchars)

    for c in password:
        c = chr(c)
        if c.isalnum():
            output += c
        else:
            output += specialchars[i % slen]
            i += 1
    return output


def main():
    try:
        f_choices = sorted(list(hashlib.algorithms_guaranteed))
        parser = argparse.ArgumentParser(description="Password scrambler")
        parser.add_argument('--file', dest="file", default=None, help="File used to initialize generation",
                            required=True)
        parser.add_argument('--login', dest="login", default=None, help="Login for which you want to use the password",
                            required=True)
        parser.add_argument('--special', dest="special", default="_&#",
                            help="Whitelist of special characters (e.g. '_&#'), default='_&#'")
        parser.add_argument('--length', dest="length", default=30, help="Length of the password, default=30", type=int)
        parser.add_argument('--loop', dest="loop", default=1, help="How many times the hashing function will be executed, default=1", type=int)
        parser.add_argument('--clip', dest="clip", default=False,
                            help="Copy the generated password into the clipboard instead of displaying", required=False,
                            action="store_true")
        parser.add_argument('--scramble-func', dest="func", default='md5', choices=f_choices,
                            help="Hashing function to use for input data scrambling, default=md5")
        args = parser.parse_args()

        # First thing first, fail if seed file does not exist
        with open(args.file, 'rb') as fd:
            raw = fd.read()
            
        # get the loop parameter, default to 1 if not set
        loop = args.loop if (args.loop > 0) else 1

        password = getpass.getpass()
        key = password.encode("utf-8")
        vec = args.login.encode("utf-8")
        for _ in range(loop):
            key = scramble(key, args.func)
            vec = scramble(vec, args.func)

        aes_out1 = aes_encrypt(vec, key, raw)

        sha_digest = hashlib.sha512(aes_out1).digest()
        passlen = len(password) % len(sha_digest)
        key2 = sha_digest[passlen: passlen + 32]

        aes_out2 = aes_encrypt(key, key2, aes_out1)

        start = key[0] % len(aes_out2)
        portion = aes_out2[start:]
        result = portion
        for x in range(loop):
            result = hashlib.sha512(result).digest()
            
        longpass = base64.b64encode(result)
        longpass = longpass[0:args.length]
        longpass = convert_to_charset(longpass, sorted(args.special, reverse=True))

        print("---")
        if not args.clip:
            print(longpass)
            print("---")
        else:
            pyperclip.copy(longpass)
            print("[INFO]: The generated password is in your clipboard.")

    except Exception as e:
        print(f"[ERROR]: {e}")


if __name__ == "__main__":
    main()
