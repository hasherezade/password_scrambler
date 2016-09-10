"""
Unit tests for password scrambler
"""
import collections
import tempfile
import unittest

from passcrambler import convert_to_charset, scramble,\
    generate_password, DEFAULT_SPECIAL_CHARS,\
    DEFAULT_PASSWORD_LENGTH, get_raw_bytes, encrypt,\
    AESCipherWrapper, scramble_and_encrypt, hash_and_encrypt, \
    digest_and_convert


class PassScramblerTestSuite(unittest.TestCase):
    """
    Test suite
    """
    def test_charset_conversion(self):
        """
        Verify password with/without special chars can be
        converted to char set
        """
        self.assertEqual(convert_to_charset(""), "")
        self.assertEqual(convert_to_charset("", DEFAULT_SPECIAL_CHARS), "")
        self.assertEqual(convert_to_charset("aa%", DEFAULT_SPECIAL_CHARS), "aa_")
        self.assertEqual(convert_to_charset("aa$", DEFAULT_SPECIAL_CHARS), "aa_")
        self.assertEqual(convert_to_charset("aaa", DEFAULT_SPECIAL_CHARS), "aaa")


    def test_key_scramble(self):
        """
        Verify scrambling logic
        """
        self.assertEqual(scramble("some_key"), "=pA,~\x9e\xa2\xd9o\xa2=O\x1f\x1f\n\x1c")
        self.assertEqual(scramble(""), "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\t\x98\xec\xf8B~")

    def test_get_raw_bytes(self):
        """
        Verify reading of raw bytes
        """
        with tempfile.NamedTemporaryFile() as passwd_file:
            passwd_file.write('lorem ipsum\n')
            passwd_file.flush()
            self.assertEqual(get_raw_bytes(passwd_file.name), "lorem ipsum\n")

    def test_encryption(self):
        """
        Verify encryption logic
        """
        aes_wrapper = AESCipherWrapper(seed='\xac\xbd\x18\xdbL\xc2\xf8\\\xed\xefeO\xcc\xc4\xa4\xd8',
                                       key=' ,\xb9b\xacY\x07[\x96K\x07\x15-#Kp')
        self.assertEqual(encrypt(aes_wrapper, "lorem ipsum \n"),
                         "rL0Y20zC+Fzt72VPzMSk2ACjst7sYiOe/gEgdfm9LQc=")

    def test_scramble_and_encrypt(self):
        """
        Verify scrambling and encryption of a password
        """
        expected_aes, expected_key = '0uFubvUqRbdGjx2la7oZU/V/t9Uwlx7XUZEd+SXP+pc=',\
                                     '\xd2\xe1nn\xf5*E\xb7F\x8f\x1d\xa5k\xba\x19S'
        with tempfile.NamedTemporaryFile() as passwd_file:
            self.assertEqual(scramble_and_encrypt("lorem", "lorem", passwd_file.name),
                             (expected_aes, expected_key))

    def test_hashing_and_encrypt(self):
        """
        Verify hashing and encryption of a password
        """
        aes, key, password = '0uFubvUqRbdGjx2la7oZU/V/t9Uwlx7XUZEd+SXP+pc=',\
                   '\xd2\xe1nn\xf5*E\xb7F\x8f\x1d\xa5k\xba\x19S', \
                   'lorem'
        expected_aes = '0uFubvUqRbdGjx2la7oZU40w4u0F2TqNqPAK7HoggtC' \
                       'JRuPOPUfRR1+Z1IBCfWh4tjq7hTIxUGUneo0qEjHz2A=='
        self.assertEqual(hash_and_encrypt(aes, password, key),
                         expected_aes)

    def test_digest_and_encrypt(self):
        """
        Verify digest and convert to scrambled password
        """
        aes, key = '0uFubvUqRbdGjx2la7oZU40w4u0F2TqNqPAK7Hoggt' \
                   'CJRuPOPUfRR1+Z1IBCfWh4tjq7hTIxUGUneo0qEjHz2A==',\
              '\xd2\xe1nn\xf5*E\xb7F\x8f\x1d\xa5k\xba\x19S'

        self.assertEqual(digest_and_convert(aes,
                                            DEFAULT_PASSWORD_LENGTH,
                                            DEFAULT_SPECIAL_CHARS,
                                            key),
                         'wcFcfP2cXoz9Kx0vlc_HbJGKkA&cWm')

    def test_generate_password(self):
        """
        Verify password generation
        """
        arg_wrapper = collections.namedtuple('Args', 'file password login special length')

        with tempfile.NamedTemporaryFile() as passwd_file:
            passwd_file.write('lorem ipsum\n')
            passwd_file.flush()
            args = arg_wrapper(file=passwd_file.name, password='lorem', login='lorem',
                               special=DEFAULT_SPECIAL_CHARS,
                               length=DEFAULT_PASSWORD_LENGTH)

            generated_password = generate_password(args)
            self.assertEqual(generated_password, 'bEsQcgB_SDC6Y0t&FYXxSawt2xZYdZ')
