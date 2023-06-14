import struct, os
import io
import sys
from bitstring import BitArray
from type1_handler import Type1
from type2_handler import Type2
import tools
from crypto import AESCipher
import binascii
import subprocess


registers = list(
    "CRC FAR FDRI FDRO CMD CTL0 MASK STAT LOUT COR0 MFWR CBC IDCODE "
    "AXSS COR8053964841 _ WBSTAR TIMER BSPI_READ FALL_EDGE _ _ BOOTSTS _ CTL1 "
    "_ DWC _ _ _ _ BSPI".split())
assert registers[0b11000] == "CTL1"
assert registers[0b10011] == "FALL_EDGE"
assert registers[0b11111] == "BSPI"
assert registers[0b01100] == "IDCODE"

opcode_list = list("NOP Read Write Reserved".split())

class DecryptParser:
    def __init__(self, stream, find_addr=None, output=None, key=None, hmac_out=True, full=False):
        self.stream = stream
        self.find_addr = find_addr
        self.print_next_payload = False
        self.decrypt_start = False
        self.decrypt_count = 0
        self.output_file = output
        self.hmac_out = hmac_out
        self.full = full
        if key is not None:
            self.cipher = AESCipher(key)
            #self.cipher = AESCipher(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xaa\xbb\xbb\xcc\xcc\xdd\xdd')
            #self.cipher = AESCipher(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        else:
            print("No Key Supplied, exitting")
            sys.exit(0)

        if output is not None:
            try:
                if os.path.getsize(output):
                    open(output,"w").close()
            except:
                open(output, "a").close()

    def handle_bit(self):
        '''

        First step in the process is to parse out the header, in the while loop is when handling the bitstream starts.

        Note that the keys for each field in the header all
        correspond to the alphabet starting from the second field.

        Read first 2 bytes, struct lib used for navigating bytes to python objects
        and converts everything to big endian assumedly for the ReWriter, but only
        this specific field (#1) is big endian in the file.
        '''
        
        print("Parsing Header")

        a, = struct.unpack(">H", self.stream.read(2))
        
        if a != 9:
            raise ValueError("Missing <0009> header, not a bit file")

        # reads next 9 bytes, according to Xilinx themselves, this is, quote - "some sort of header"
        unk = self.stream.read(a)  # unknown data
        
        # this next read field must evalaute to 1
        b, = struct.unpack(">H", self.stream.read(2))
        if b != 1:
            raise ValueError("Missing <0001> header, not a bit file")
        self.handle_bitstart(a, unk, b)

        while True:
            '''
             Here is where we can start to loop over each field.
             At the beginning of the loop the parser takes out the key.
            
             Keys are a 1 byte value starting with ascii letter 'a'(0x61) through 'e'(0x65)
             there may be keys afterwards so the loop handles unknowns as well.
            '''
            key = self.stream.read(1)

            if not key:
                # loop closes when the byte read from where a Key should be is 0x00. 
                break
            self.handle_keystart(key)
            if key == b"e":
                length, = struct.unpack(">I", self.stream.read(4))
                length = length * 8 
                self.handle_binstart(length)
                self.handle_bin(end_at=length)
                break
            elif key in b"abcd":
                data = self.stream.read(*struct.unpack(">H",
                    self.stream.read(2)))
                self.handle_meta(key, data)
            else:
                print("Unknown key: {}".format(key))

    def handle_bitstart(self, a, unk, b):
        pass

    def handle_keystart(self, key):
        pass

    def handle_meta(self, key, data):
        assert data.endswith(b"\x00")
        data = data[:-1].decode()
        name = {
                b"a": "Design",
                b"b": "Part name",
                b"c": "Date",
                b"d": "Time"
                }[key]
        print("{}: {}".format(name, data))

    def handle_binstart(self, length):
        print("Bitstream payload length: {:#x}".format(length))
    
    '''
     This function takes care of what goes on after the 'e' key i read.
     Author assumes no extraneous keys.
    '''
    def handle_bin(self, end_at=None):
        sync = b""
        count = 0
        # read to SYNC word
        while not sync.endswith(b"\xaa\x99\x55\x66"):
            sync += self.stream.read(1)
            count = count + 1 
        print("Padded words before SYNC: {}".format((count/4 - 1)))
 
        first_block = True
        HMAC_KEY = b''
        IPAD_BLOCK = b'\x36'*16
        OPAD_BLOCK = b'\x5c'*16
        '''
         Here begins actual packet parsing
        '''
        while True:

            '''
             end_at is defined as the current length of the stream + the payload length defined in the header.
             This case passes when the loop parses out the entirity of the remaining bytes 
            '''
            if end_at is not None and self.stream.tell() >= end_at:
                assert self.stream.tell() == end_at
                break
            hdr = self.stream.read(4)
            

            if len(hdr) != 4:
                assert end_at is None
                assert len(hdr) == 0
                break
            hdr_un, = struct.unpack(">I", hdr)
            typ = hdr_un >> 29 # first 3 bits are the packet type `001` == Type 1, `010` == Type 2
            if typ == 1 and not self.decrypt_start:
                self.handle_type1(hdr_un)
            elif typ == 2 and not self.decrypt_start:
                self.handle_type2(hdr_un)
            else: 
                '''
                    Decryption Section
                '''
                # read in more cipher text to 16 bytes
                ciphertext = hdr + self.stream.read(12)

                # if this is the very first block being decrypted, it is the HKEY
                try:
                    plaintext = self.cipher.decrypt_word(ciphertext, iv=self.CBC_IV, xor=False, swap=True)

                    if first_block:
                        HMAC_KEY += tools.xor_bytes(plaintext, IPAD_BLOCK)
                        first_block = False
                        second_block = True
                    elif second_block:
                        HMAC_KEY += tools.xor_bytes(plaintext, IPAD_BLOCK)
                        second_block = False
                        print("HMAC Key: {}".format(HMAC_KEY.hex()))
                except:
                    print("Unexpected error when decrypting bytes - ", ciphertext)
                    print("End of file may have been reached")
                    sys.exit(0)

                if plaintext == IPAD_BLOCK or plaintext == OPAD_BLOCK:
                    if self.hmac_out:
                        self.write_decrypted_bin(self.cipher.decrypt_word(ciphertext,iv=self.CBC_IV,xor=True))
                if self.output_file:
                    self.write_decrypted_bin(plaintext)

                self.CBC_IV = ciphertext

                self.decrypt_count -= 4
                # Stop decryption 
                if self.decrypt_count == 0:
                    break
        
        self.handle_end() 

    def write_decrypted_bin(self, pt):
        with open(self.output_file, "ab") as f:
            f.write(pt)

    def handle_sync(self, sync):
        pass

    def handle_end(self):
        pass
    
    '''
     Type 1 Packets are for declaring reads and writes.
     they appear to be used as a 'header' that is defining
        the operation that is about to happen. Must always
        be followed by a Type 2 Packet if payload is larger than
        11 bit length worth of words.
    '''
    def handle_type1(self, hdr):
        '''
         Type 1 Header(32 bits):
          31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
          T  T  T  O  O  RA RA RA RA RA RA RA RA RA  A  A  A  A  A  R  R  W  W  W  W  W  W  W  W  W  W  W
        
         T  = Header Type
         O  = Opcode
         RA = Reserved Register Address Bit
         A  = Register Address Bit
         R  = Reserved Bit
         W  = Word Count (# of 32 bit words to follow header)
        '''
        
        packet = Type1()

        # bit shifting the header bits, the & 0x3 is simply there to condense the remainder to 2 bits
        op = (hdr >> 27) & 0x3
        #print("Before 0x3: ", "{0:b}".format(op))
        
        # Applies mask a to the register field of the hdr.
        # Only the least significant 5 bits of the field are writable - the others are reserved.
        self.addr = (hdr >> 13) & 0x7ff 
        
        assert self.addr == self.addr & 0x1f
        
        # this mask gets the first 11 bits which corresponds to length (in bytes)
        length = hdr & 0x7ff

        payload = self.stream.read(length * 4)

        assert len(payload) == length * 4
         
        packet.raw_header = hdr
        packet.register  = self.addr
        packet.op        = op
        packet.payload   = payload
        packet.p_length  = length
 
        packet.handle() 
        

        '''
            If the register we just hit was the CBC register, we need to store that value since the payload
            is the IV for the bitstream
        '''
        if registers[self.addr] == "CBC": 
            self.CBC_IV = packet.CBC_IV 
            print("Initial IV: 0x{}".format(packet.CBC_IV.hex()))
        '''
			Once we hit the DWC register, we know that the next bytes read
			are the beginning of the encrypted ciphertext.
        '''
        if registers[self.addr] == "DWC":
            self.decrypt_start = True
            self.decrypt_count = int.from_bytes(packet.payload, 'big')
            print("Decrypted Word Count: 0x{}".format(packet.payload.hex()))        

        #self.handle_op(op, hdr, payload)
    
    '''
     Type 2 Packets follow Type 1 packets when the payload is too large.
     These packets use the address defined by he previous Type 1 packet.
     
     Header 32(bits):
      31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
       T  T  O  O  W  W  W  W  W  W  W  W  W  W  W  W  W  W  W  W  W  W  W  W  W  W  W  W  W  W  W  W

     T = Header Type
     O = Opcode
     W = Word Count (# of 32 bit words to follow header)
    
    '''
    def handle_type2(self, hdr):
        op = (hdr >> 27) & 0x3
        length = hdr & 0x7ffffff
        payload = self.stream.read(length * 4)
        assert len(payload) == length * 4
        print("Handling type 2 OP: ", opcode_list[op])
        #self.handle_op(op, hdr, payload)
        
        packet = Type2()
        packet.op          = op
        packet.p_length    = length
        packet.payload     = payload
        packet.current_FAR = self.current_FAR
        packet.handle()

    def handle_op(self, op, hdr, payload):
        # OP Codes -
        # 00 : NOP
        # 01 : Read
        # 10 : Write
        # 11 : Reserved 
        assert op != 3
        if op == 0:
            self.handle_nop(hdr, payload)
        elif op == 1:
            self.handle_read(hdr, payload)
        elif op == 2:
            #print("HDR: ", hdr, " payload: ", payload)
            ok = handle_write(hdr, payload)
            print("out of handle_write call")     
            print("OK:", ok)
        return 1

    def handle_nop(self, hdr, payload):
        pass

    def handle_read(self, hdr, payload):
        pass

def handle_write(hdr, payload): 
    #print("Payload: ", BitArray(bytes=payload).hex) 
    return 1


if __name__ == "__main__":
    
    import argparse
    parser = argparse.ArgumentParser(
    description="Xilinx Bitstream decryptor and hmac calculator")
    parser.add_argument("bitfile", metavar="BITFILE",
                        help="Input bit file name")
    parser.add_argument("--output", type=str, help="Output bin file name", default=None)
    parser.add_argument("--key", type=str, help="AES Key, input as string ex)"+"".join("\%02x" % i for i in b'pppp')) 
    parser.add_argument("--hmac_out", type=bool, help="writes HMAC header to binary out file", default=False)
    parser.add_argument("--full", type=bool, help="Decrypt PAST HMAC section (not for use with digest).", default=False)
    args = parser.parse_args()

    # 1. Read into io.BytesIO Object
    read = io.BytesIO(open(args.bitfile, "rb").read())
    decryptor = DecryptParser(read, output=args.output, key=args.key, hmac_out=args.hmac_out, full=args.full)
    decryptor.handle_bit()
    
    read.seek(0)

