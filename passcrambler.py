#!/usr/bin/env python2.7

import sys
import os
import argparse
import getpass
import base64
import hashlib
from Crypto.Cipher import AES

###
# AES:

pad = lambda s: s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def aes_encrypt( seed, key, raw ):
    raw = pad(raw)
    iv = seed[0:AES.block_size]
    cipher = AES.new( key, AES.MODE_CBC, iv )
    return base64.b64encode( iv + cipher.encrypt( raw ) ) 

###

def scramble( key, func='md5' ):
    # Ugly but effective, moreover this is not a webapp so who cares.
    # Will raise AttributeError if function is not valid ... auto validation FTW!
    return eval( 'hashlib.%s(key).digest()' % func )

###

def convert_to_charset(password, specialchars):
    output = ""
    i      = 0
    slen  = len(specialchars)

    for c in password:
        if c.isalnum():
            output += c
        else:
            output += specialchars[i % slen]
            i += 1

    return output        
   
def main():
    try:
        parser = argparse.ArgumentParser(description="Password scrambler")
        parser.add_argument('--file', dest="file", default=None, help="File used to initialize generation", required=True)
        parser.add_argument('--login', dest="login", default=None, help="Login for which you want to use the password", required=True)
        parser.add_argument('--special', dest="special", default="_&#", help="Whitelist of special characters, i.e: '_&#'")
        parser.add_argument('--length', dest="length", default=30, help="Length of the password, default=30", type=int)
        parser.add_argument('--scramble-func', dest="func", default='md5', help="Hashing function to use for input data scrambling, default=md5.\nOther functions can be found on hashlib module documentation.")
        args = parser.parse_args()

        # first thing first, fail if seed file does not exist
        with open( args.file, 'rb' ) as fd:
            raw = fd.read()

        password = getpass.getpass()
        key = scramble( password, args.func )    
        vec = scramble( args.login, args.func )

        aes_out1 = aes_encrypt( vec, key, raw )

        sha_digest = hashlib.sha512(aes_out1).digest()
        passlen    = len(password) % len(sha_digest)
        key2       = sha_digest[passlen: passlen+32]

        aes_out2 = aes_encrypt( key, key2, aes_out1 )
        
        start    = ord(key[0]) % len(aes_out2)
        portion  = aes_out2[start:]
        result   = hashlib.sha512(portion).digest()
        longpass = base64.b64encode(result)
        longpass = longpass[0:args.length]
        longpass = convert_to_charset(longpass,  sorted(args.special, reverse=True))

        print "---"
        print longpass
        print "---"

    except AttributeError:
        print "[ERROR] '%s' is not a valid hashing function." % args.func

    except Exception as e:
        print "[ERROR] %s" % e

if __name__ == "__main__":
    main()

