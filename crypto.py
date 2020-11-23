from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto import Random
from Crypto.Cipher import AES
from binascii import hexlify, unhexlify
import struct
import operator
# Padding for the input string --not
# related to encryption itself.
BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class AESCipher:
    """
    Usage:
        c = AESCipher('password').encrypt('message')
        m = AESCipher('password').decrypt(c)

    Tested under Python 3 and PyCrypto 2.6.1.

    """

    def __init__(self, key=None):
        self.key = key

    
    def encrypt(self, raw):
        AES_IV = b'\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c'
        cipher = AES.new(self.key, AES.MODE_CBC, AES_IV)
        return cipher.encrypt(raw)
   

    def decrypt(self, enc, iv=None, xor=True):
          
        XOR = bytearray(b'\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c\x6c') 
     
        AES_IV = self.swapBytes(bytes(iv))[0:16]
        if xor: 
            key = bytes(map(operator.xor, AES_IV, XOR)) 
        else:
            key = bytes(AES_IV) 
        
       
        cipher = AES.new(self.key, AES.MODE_CBC, key)
        plain = cipher.decrypt(enc)
         
        return plain


    def decrypt_word(self, enc, iv=None, xor=True, swap=True): 
 
        '''
            To decrypt Xilinx FPGA bitstreams
            1 - swap the encrypted text by word and bits
            2 - swap the IV by word and bits
            3 - XOR the IV with 0x6c6c6c..
            4. - decrypt using AES CBC Algo with XOR'd IV
            5. - swap word and bits again to get the plaintext
        '''

        enc = bytes(self.swapBytes(enc)[0:16]) 
        res = self.decrypt(enc[0:16], iv=iv, xor=xor) 
        if swap:
            return self.swapBytes(res)[0:16]
        else:
            return res[0:16]



    # receive 32 bit bytearray and return bitswapped
    def swapBits(self, word):
        word_swapped = bytearray() 
        for each in range(4):
            each_int = word[each]
            each_int = int(format(each_int, '#010b')[:1:-1], 2)
            #print(each_int)
            word_swapped.append(each_int)
            #print(word_swapped)
        return word_swapped
  
    # receive 16 byte bytearray and return byteswapped and bitswapped
    def swapBytes(self, bytearray_pre):
        bytearray_post = bytearray(len(bytearray_pre))         
        bytearray_post[0:3] = bytearray_pre[3],bytearray_pre[2],bytearray_pre[1],bytearray_pre[0]
        bytearray_post[0:3] = self.swapBits(bytearray_post[0:4])
        bytearray_post[4:7] = bytearray_pre[7],bytearray_pre[6],bytearray_pre[5],bytearray_pre[4]
        bytearray_post[4:7] = self.swapBits(bytearray_post[4:8])
        bytearray_post[8:11] = bytearray_pre[11],bytearray_pre[10],bytearray_pre[9],bytearray_pre[8]
        bytearray_post[8:11] = self.swapBits(bytearray_post[8:12])
        bytearray_post[12:15] = bytearray_pre[15],bytearray_pre[14],bytearray_pre[13],bytearray_pre[12]
        bytearray_post[12:15] = self.swapBits(bytearray_post[12:16])
        return bytearray_post

def flip32(data):
    sl = struct.Struct("<I")
    sb = struct.Struct(">I")
    b = memoryview(data)
    d = bytearray(len(data))
    for offset in range(0, len(data), sl.size):
         sb.pack_into(d, offset, *sl.unpack_from(b, offset))
    return d


if __name__ == "__main__":
    cipher = AESCipher(key = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    IV            = bytearray(b'\x01\x23\x34\x67\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')   
  
    print("Cipher: ", hexlify(cipher.key))
    print("IV: ", hexlify(IV))
    BITSTREAM_block   = b'\xa9\xa5\x81\xcf\x45\xd9\x0b\xd4\x3d\x66\xa1\x64\xa9\x69\x03\xa4'
    print("Bitstream Block: ", hexlify(BITSTREAM_block)) 
    
    plaintext = cipher.decrypt_word(BITSTREAM_block, iv=IV)   
    print("Plaintext Block 1: ", hexlify(plaintext))

    BITSTREAM_block_2 = b'\xef\xab\xb3\xb6\x0d\x7f\xc4\x10\xa7\x1a\x58\x99\xea\x4b\x0a\xd6'  
    plaintext = cipher.decrypt_word(BITSTREAM_block_2, iv = BITSTREAM_block, xor=False)
    print("Plaintext Block: ", hexlify(plaintext))

    BITSTREAM_block_3 = b'\xff\x8b\xc2\x6a\x3b\x17\x91\x75\xea\x77\x0a\xa2\xd7\x26\x54\xa4'
    plaintext = cipher.decrypt_word(BITSTREAM_block_3, iv = BITSTREAM_block_2, xor=False)
    print("Plaintext Block 3: ", hexlify(plaintext)) 
