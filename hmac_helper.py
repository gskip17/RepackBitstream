import hashlib, binascii, hmac
import sys, os, io
from binascii import hexlify 
import crypto 
import operator
import struct

CHUNK_SIZE = 16

class HashHelper(object):

    def __init__(self, stream, hkey=None):
        self.stream = stream
        self.crypto_helper = crypto.AESCipher()  
        
        if hkey is not None:
            self.hkey = hkey
        else:
            raise AttributeError("Must Supply an HMAC Key <self.hkey> to object initialization")
        
        self.sha256 = None
        #self.sha256 = hmac.HMAC(key=self.hkey, digestmod="SHA256")
        return
    
    def calc_digest(self):
        self.sha256 = hmac.HMAC(key=self.hkey, digestmod="sha256")
        try:
            word = self.stream.read(CHUNK_SIZE)
            while word:
                
                self.sha256.update(word) 
                word = self.stream.read(CHUNK_SIZE)
                digest = self.sha256.hexdigest()
        finally:
            print("Finished, closing file.")
            self.stream.close()

        print("Digest Finished")
        print("Digest Value", binascii.hexlify(self.sha256.digest()))
        print("Digest Size", self.sha256.digest_size)
        print("Block Size", self.sha256.block_size)

        return(self.sha256.digest())

if __name__ == "__main__":
    print("Remember to hard code an hkey to test with this file")
    stream = io.BytesIO(open("temp_decrypted.bin", "rb").read())
    h = HashHelper(stream, hkey=b'')
    h.calc_digest()


