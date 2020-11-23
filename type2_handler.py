from bitstring import BitArray
import logging
import struct

split_n = lambda x, n: [x[i:i+n] for i in range(0, len(x), n)]
zero_word = "00000000000000000000000000000000"
class Type2:
    def __init__(self, op=None, payload=None, p_length=None, current_FAR=None):
 
        self.op          = op
        self.payload     = payload
        self.p_length    = p_length
        self.current_FAR = current_FAR

        logging.basicConfig(filename='bit_stream.log',level=logging.DEBUG)

        return

    '''
        Main Packet Handler
    '''
    def handle(self):
        logging.info("*****  PACKET (Type 2)  *****")
        self.handle_op()
        return

    def handle_op(self):
        # OP Codes -
        # 00 : NOP
        # 01 : Read
        # 10 : Write
        # 11 : Reserved 
        assert self.op != 3
        if self.op == 0:
            logging.info("Type 2 NOP OP: %d", self.op)
            pass
            #self.handle_nop(hdr, payload)
        elif self.op == 1:
            logging.info("Type 2 Read OP: %d", self.op)
            pass
            #self.handle_read(hdr, payload)
        elif self.op == 2:
            logging.info("Type 2 Write OP: %d", self.op)
            ok = self.handle_write()
        return 1

    def handle_write(self):
        logging.info("Type 2 Payload - ")
        logging.info( "---- Payload Len %d", self.p_length)
        #split_payload = '\n'.join(split_n(BitArray(bytes=self.payload).bin, 32))
        #logging.info(" ---- Payload: \n%s", split_payload)        
        split_payload = split_n(BitArray(bytes=self.payload).bin, 32)
        self.payload_content_log(split_payload)
        
        return 1
    
    '''
        Logs none zero words of payload along with address.
    '''
    def payload_content_log(self, payload):
        logging.info(" ---- None Zero Words and Address (guess)")
        logging.info(" ---- Starting FAR: \n\
         -------- Top/Bottom: %s \n\
         -------- Row: %s \n\
         -------- Column: %s \n\
         -------- Minor Address: %s\n\
		 -------- Word: %s\n\
         ---- TOTAL FRAME COUNT: %d\n", 
         self.current_FAR['top_bottom'], self.current_FAR['row_addr'], self.current_FAR['col_addr'], self.current_FAR['minor_addr'], self.current_FAR['word'], len(payload) / 101)
        
        current_address = BitArray(bin=self.current_FAR['word'])
        word_count = 1 
        frame_count = 0
         
        logging.info("<---- BEGIN FRAME 0 ---->")

        for word in payload:
            
            if True: #word != zero_word:
                if word_count % 101 == 0:
                    word_count == word_count + 1 
                    logging.info("<---- END FRAME %d, words in frame: %d  ---->\n", frame_count, 101 if word_count % 101 == 0 else word_count % 101)
                    frame_count = frame_count + 1
                    logging.info("<---- BEGIN FRAME %d ---->", frame_count)

                logging.info(" ---- Address Word: %s \n           ----    Data Word: %s", current_address.bin, word)
                current_address = BitArray(int=(current_address.int + 1), length=32)
                word_count = word_count + 1

