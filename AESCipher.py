import base64
from Crypto.Cipher import AES
from Crypto import Random
'''
Thanks to:
   http://stackoverflow.com/a/12525165
'''
'''
Using IV for having always a different output also for the same input.
The IV is *NOT* included in the output.
The AES CBC doesn't use the PKCS#7-padding. This garant 1 more byte in the decrypted_payload!
Note: you can use os.urandom(24) for generating an enough good random bytes string 

'''


class AESCipher:
    """Class used for encryption/decryption.

    Note:
        Padding is disabled by default to have 1 more bytes, you can enable
        it by passing as arguments on encrypt/decrypt method padding = True
    """

    def __init__(self, key):
        self.key = key

    def set_iv(self, iv):
        self.iv = iv

    def pad(self, s):  # The lenght of an input have to be a multiple of BlockSize (16)
        # Add padd if necessary
        return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

    def unpad(self, s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, raw, padding = False):

        if padding:
            raw = self.pad(raw)
        #iv = Random.new().read(AES.block_size)
        iv = self.iv
        cipher = AES.new(self.key, AES.MODE_CBC, iv)  # One of the most secure of AES: CBC with IV
        return cipher.encrypt(raw)

    def decrypt(self, enc, padding = False):  # Simple decrypt function
        #iv = enc[:16]
        iv = self.iv
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        if padding:
            return self.unpad(cipher.decrypt(enc))
        else:
            return cipher.decrypt(enc)
"""
iv = Random.new().read(AES.block_size)
    b'\xef\xaa)\x9fHQ\x0f\x04\x18\x1e\xb5;B\xff\x1c\x01'
iv.hex()
    'efaa299f48510f04181eb53b42ff1c01'
bytearray.fromhex(iv.hex())
    bytearray(b'\xef\xaa)\x9fHQ\x0f\x04\x18\x1e\xb5;B\xff\x1c\x01')
"""