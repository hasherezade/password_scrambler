Password scrambler
==========
Small utility to generate complicated passwords<br/>
(see also the GUI edition: https://hasherezade.github.io/passcrambler/ )<br/>

Benefits
-
+ You get <b>more secure password</b>- long, not from dictionary, etc i.e 'txork9Zfa8yXc_lMbb1LCHPZIH7wE1'<br/>
+ Yet, <b>you don't have to remeber it</b> - you must remember only your easy password and document that you used as a generation base<br/>
+ You <b>may reuse</b> the easy password and the base file - still, for different login@domain you will get a totally new long password
+ It is not saving your complicated password anywhere, so nobody can steal it and decrypt - it generates it by hasing function and you just need to copy it and login where you want<br/>
+ Open source, written in python - nothing is hidden under the hood, <b>everyone can review it before using</b> and make custom changes in code</br>

Installation
-

1. Install Python 3 and PIP
2. Clone this repository
3. Go inside the repository and install the requirements: 
```console
pip install -r requirements.txt
```

How it works
-
<pre>
./passcrambler.py --help
usage: passcrambler.py [-h] --file FILE --login LOGIN [--special SPECIAL]
                       [--length LENGTH] [--clip] [--scramble-func FUNC]

Password scrambler

optional arguments:
  -h, --help            show this help message and exit
  --file FILE           File used to initialize generation
  --login LOGIN         Login for which you want to use the password
  --special SPECIAL     Whitelist of special characters (e.g. '_&#'), default='_&#'
  --length LENGTH       Length of the password, default=30
  --clip                Copy the generated password into the clipboard instead
                        of displaying
  --scramble-func       {blake2b,blake2s,md5,sha1,sha224,sha256,sha384,sha3_224,
                         sha3_256,sha3_384,sha3_512,sha512,shake_128,shake_256}
                        Hashing function to use for input data scrambling, default=md5
</pre>
example:
<pre>
./passcrambler.py --file MyPhoto.jpg --login hasherezade@hasherezade.net
Password: _password123_
---
txork9Zfa8yXc_lMbb1LCHPZIH7wE1
---
</pre>
Typical scenario:
-
+ I need to generate a new password i.e. for my e-mail
+ I have to prepare 2 things : an easy password, that I will remember and some document, that I have to keep safe without changes
+ I deploy password scrambler giving as an input my login and a document
+ I am prompted for the easy password, so I type it
+ I copy generated password and change it in my e-mail service
+ Wherever I need to re-login I just deploy scrambler with same parameters, and it will regenerate the same hash

