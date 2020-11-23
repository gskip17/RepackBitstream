from bitstring import BitArray
import logging
import struct 
import json

split_n = lambda x, n: [x[i:i+n] for i in range(0, len(x), n)]

type1_registers = list(
    		"CRC FAR FDRI FDRO CMD CTL0 MASK STAT LOUT COR0 MFWR CBC IDCODE "
    		"AXSS COR1 _ WBSTAR TIMER BSPI_READ FALL_EDGE _ _ BOOTSTS _ CTL1 "
    		"_ DWC _ _ _ _ BSPI".split()) 

opcode_list = list("NOP Read Write Reserved".split())

command_register_codes = [ 
            ["NULL","Null command, does nothing"], # 00000
            ["WCFG","Writes Configuration Data: used prior to writing configuration data to the FDRI."], # 00001
            ["MFW", "Multiple Frame Write: used to perform a write of a single frame data to multiple frame addresses."], #00010
            ["DGHIGH/LFRM","Last Frame: Deasserts the GHIGH_B signal, activating all interconnects. The GHIGH_B signal is asserted with the AGHIGH command."], #00011
            ["RCFG", "Reads Configuration Data: used prior to reading configuration data from the FDRO."], #00100
            ["START","Begins the Startup Sequence: The startup sequence begins after a successful CRC check and a DESYNC command are performed"], #00101
            ["RCAP", "Resets the CAPTURE signal after performing readback-capture in single-shot mode."], #00110
            ["RCRC", "Resets CRC: Resets the CRC register"], #00111
            ["AGHIGH", "Asserts the GHIGH_B signal: places all interconnect in a High-Z \
            state to prevent contention when writing new configuration data. \
            This command is only used in shutdown reconfiguration. \
            Interconnect is reactivated with the LFRM command."], #01000
            ["SWITCH", "Switches the CCLK frequency: updates the frequency of the master CCLK to the value specified by the OSCFSEL bits in the COR0 register."], #01001
            ["GRESTORE","Pulses the GRESTORE signal: sets/resets (depending on user configuration) IOB and CLB flip-flops."], #01010
            ["SHUTDOWN", "Begin Shutdown Sequence: Initiates the shutdown sequence,\
            disabling the device when finished. Shutdown activates on the next \
            successful CRC check or RCRC instruction (typically an RCRC \
            instruction)."], #01011
            ["GCAPTURE","Pulses GCAPTURE: Loads the capture cells with the current register states"], #01100
            ["DESYNC",  "Resets the DALIGN signal: Used at the end of configuration to desynchronize the device. After desynchronization, all values on the configuration data pins are ignored."], #01101
            ["Reserved", "Reserved"], #01110
            ["IPROG", "Internal PROG for triggering a warm boot"], #01111
            ["CRCC", "When readback CRC is selected, the configuration logic recalculates \
            the first readback CRC value after reconfiguration. Toggling \
            GHIGH has the same effect. This command can be used when \
            GHIGH is not toggled during the reconfiguration case."], #10000
            ["LTIMER","Reload Watchdog timer."], #10001
            ["BSPI_READ","BPI/SPI re-initiate bitstream read."], #10010
            ["FALL_EDGE","Switch to negative-edge clocking (configuration data capture on falling edge)."] #10011
            ]

FAR_block_types = list("CLB/IO/CLK RAM CFG_CLB Reserved".split())


class Type1:
    def __init__(self, register=None, op=None, payload=None, p_length=None):
        
        self.register    = register
        self.op          = op
        self.payload     = payload
        self.p_length    = p_length 
        self.current_FAR = None

        logging.basicConfig(filename='bit_stream.log',level=logging.DEBUG)
        
        return
    
    '''
        Main Packet Handler
    '''
    def handle(self):
        logging.info("*****  PACKET *****")
        logging.info(" Raw Header: %s", '{:08b}'.format(self.raw_header))
        self.handle_op()

        return

    def handle_reg(self):
        reg = type1_registers[self.register]
        logging.info("Register: %s  %s", reg, "{0:b}".format(self.register))
        
        if reg == "CMD":
            self.parse_command()
        elif reg == "COR0":
            self.parse_COR0()
        elif reg == "COR1":
            self.parse_COR1()
        elif reg == "IDCODE":
            self.parse_IDCODE()
        elif reg == "MASK":
            self.parse_MASK()
        elif reg == "FAR":
            self.parse_FAR()
        elif reg == "MFWR":
            self.parse_MFWR()
        elif reg == "FDRI":
            self.parse_FDRI()
        elif reg == "CTL1":
            self.parse_CTL1()
        elif reg == "STAT":
            self.parse_STAT()
        elif reg == "CRC":
            self.parse_CRC()
        elif reg == "IDCODE":
            self.parse_IDCODE()
        elif reg == "CBC":
            self.parse_CBC()
        elif reg == "DWC":
            self.parse_DWC()

        return reg


    def handle_op(self):
        # OP Codes -
        # 00 : NOP
        # 01 : Read
        # 10 : Write
        # 11 : Reserved 
        assert self.op != 3
        if self.op == 0:
            logging.info("Begin NOP OP: %d", self.op)
            pass
            #self.handle_nop(hdr, payload)
        elif self.op == 1:
            logging.info("Begin Read OP: %d", self.op)
            pass
            #self.handle_read(hdr, payload)
        elif self.op == 2:
            logging.info("Begin Write OP: %d", self.op)
            ok = self.handle_write()  
        return 1
   
    def handle_write(self):
        register = self.handle_reg()
        #print("Payload: ", BitArray(bytes=self.payload).hex)
        return 1

    def parse_command(self):
        
        cmd = command_register_codes[BitArray(bytes=self.payload).int]
        logging.info("Write COMMAND %s", cmd[0])
        logging.info("CMD info: %s", cmd[1])
    
    def parse_COR0(self):
        logging.info("COR0 Info - ")
        self.payload_bytes = BitArray(bytes=self.payload).int 
        PWRDWN_STAT = self.payload_bytes >> 27 & 0x1
        DONE_PIPE   = self.payload_bytes >> 25 & 0x1
        DRIVE_DONE  = self.payload_bytes >> 24 & 0x1
        SINGLE      = self.payload_bytes >> 23 & 0x1
        OSCFSEL     = self.payload_bytes >> 17 & 0x3f
        SSCLKSRC    = self.payload_bytes >> 15 & 0x3
        DONE_CYCLE  = self.payload_bytes >> 12 & 0x7
        MATCH_CYCLE = self.payload_bytes >> 9  & 0x7
        LOCK_CYCLE  = self.payload_bytes >> 6  & 0x7
        GTS_CYCLE   = self.payload_bytes >> 3  & 0x7
        GWE_CYCLE   = self.payload_bytes       & 0x7
        
        logging.info("COR0 Configuration: \n\
            PWRDWN_STATE: %d \n\
            DONE_PIPE: %d \n\
            DRIVE_DONE: %d \n\
            SINGLE: %d \n\
            OSCFSEL: %d \n\
            SSCLKSRC: %d \n\
            DONE_CYCLE: %d \n\
            MATCH_CYCLE: %d \n\
            LOCK_CYCLE: %d \n\
            GTS_CYCLE: %d", PWRDWN_STAT, DONE_PIPE, DRIVE_DONE, SINGLE, OSCFSEL, SSCLKSRC, DONE_CYCLE, MATCH_CYCLE, LOCK_CYCLE, GTS_CYCLE)
    def parse_CTL1(self):
        logging.info("CTL1 Info - ")
        self.payload_bytes = BitArray(bytes=self.payload).int
        EFUSE_KEY           = self.payload_bytes >> 31 & 0x1
        ICAP_SELECT         = self.payload_bytes >> 30 & 0x1
        OverTempPowerDown   = self.payload_bytes >> 12 & 0x1
        ConfigFallback      = self.payload_bytes >> 10 & 0x1
        GLUTMASK_B          = self.payload_bytes >>  8 & 0x1
        FARSRC              = self.payload_bytes >>  7 & 0x1
        DEC                 = self.payload_bytes >>  6 & 0x1
        SBITS               = self.payload_bytes >>  4 & 0x3
        PERSIST             = self.payload_bytes >>  3 & 0x1
        GTS_USER_B          = self.payload_bytes       & 0x1

        logging.info("CTL1 Configuration: \n\
            EFUSE_KEY: %d \n\
            ICAP_SELECT: %d \n\
            OverTempPowerDown: %d \n\
            ConfigFallback: %d \n\
            GLUTMASK_B: %d \n\
            FARSRC: %d \n\
            DEC: %d \n\
            SBITS: %d \n\
            PERSIST: %d \n\
            GTW_USER_B: %d", EFUSE_KEY, ICAP_SELECT, OverTempPowerDown, ConfigFallback, GLUTMASK_B, FARSRC, DEC, SBITS, PERSIST, GTS_USER_B)
        

    def parse_COR1(self):
        logging.info("COR1 Info - ")
        self.payload_bytes = BitArray(bytes=self.payload).int
        PERSIST_DEASSERT_AT_DESYNC = self.payload_bytes >> 17 & 0x1
        RBCRC_ACTION               = self.payload_bytes >> 15 & 0x3
        RBCRC_NO_PIN               = self.payload_bytes >> 9  & 0x1
        RBCRC_EN                   = self.payload_bytes >> 8  & 0x1
        BPI_1ST_READ_CYCLE         = self.payload_bytes >> 2  & 0x3
        BPI_PAGE_SIZE              = self.payload_bytes       & 0x3

        logging.info("COR1 Configuration: \n\
            PERSIST_DEASSERT_AT_DESYNC: %d \n\
            RBCRC_ACTION: %d \n\
            RBCRC_NO_PIN: %d \n\
            RBCRC_EN: %d \n\
            BPI_1ST_READ_CYCLE: %d \n\
            BPI_PAGE_SIZE: %d", PERSIST_DEASSERT_AT_DESYNC, RBCRC_ACTION, RBCRC_NO_PIN, RBCRC_EN, BPI_1ST_READ_CYCLE, BPI_PAGE_SIZE)
    
    def parse_IDCODE(self):
        logging.info("IDCODE Info -")
        idcode = BitArray(bytes=self.payload).hex
        logging.info(" ---- %s ", idcode)
    
    def parse_MASK(self):
        logging.info("MASK Info -")
        bitmask = BitArray(bytes=self.payload).bin
        logging.info(" ---- %s ", bitmask)
    
    def parse_FAR(self):
        logging.info("FAR info - ")
        self.payload_bytes = BitArray(bytes=self.payload).int
        reserved       = self.payload_bytes >> 26
        block_type     = self.payload_bytes >> 23 & 0x3
        top_bottom_bit = self.payload_bytes >> 22 & 0x1
        row_addr       = self.payload_bytes >> 17 & 0x1f
        col_addr       = self.payload_bytes >> 7  & 0x3ff
        minor_addr     = self.payload_bytes       & 0x7f

        block_type_str = FAR_block_types[block_type]

        logging.info("FAR Configuration: \n\
            Reserved Bits: %s\n\
            Block Type: %s \n\
            Top Bottom Bit: %d \n\
            Row Address: %s \n\
            Column Address: %s \n\
            Minor Address: %s", reserved, block_type_str, top_bottom_bit, hex(row_addr), hex(col_addr), hex(minor_addr))
        
        self.current_FAR = {"block_type": block_type_str,
                            "top_bottom": top_bottom_bit,
                            "row_addr"  : hex(row_addr),
                            "col_addr"  : hex(col_addr),
                            "minor_addr": hex(minor_addr),
                            "word"      : BitArray(bytes=self.payload).bin}

    def parse_MFWR(self):
        logging.info("MFWR info - ")
        logging.info(" ---- MFWR Payload Len: %d", self.p_length)
        split_payload = '\n'.join(split_n(BitArray(bytes=self.payload).bin, 32))
        logging.info(" ---- Payload: \n%s", split_payload)
    
    def parse_FDRI(self):
        logging.info("FDRI info - ")
        logging.info( "---- FDRI Payload Len %d", self.p_length)
        split_payload = '\n'.join(split_n(BitArray(bytes=self.payload).bin, 32))
        logging.info(" ---- Payload: \n%s", split_payload)
        
        try:
            intensity = BitArray(bytes=self.payload).int
        except Exception as e:
            print("Could not get Intensity")
        #if intensity > 1:
        #    logging.info(" ----- Configuration In frame -----")
            
        with open("configured_frames.json", 'a') as f:
            item = self.last_FAR
            item['payload'] = BitArray(bytes=self.payload).bin
            json.dump(item, f)
            f.write(',')
            '''
            with open("configured_frames.txt", 'a') as f:
                f.write("------ Configuration Frame -------\n\
                        FAR - \n\
                        Block Type: " + self.last_FAR['block_type'] + "\n\
                        Top Bottom: " + str(self.last_FAR['top_bottom']) + "\n\
                        Row: " + self.last_FAR['row_addr'] + "\n\
                        Column: " + self.last_FAR['col_addr'] + "\n\
                        Minor: " + self.last_FAR['minor_addr'] + "\n\
                        Payload: " + split_payload + "\n")
            '''

    def parse_CRC(self):
        logging.info("CRC info -")
        self.payload_bytes = BitArray(bytes=self.payload)
        logging.info("CRC Payload: %s", self.payload_bytes)

    def parse_IDCODE(self):
        logging.info("IDCODE info -")
        self.payload_bytes = BitArray(bytes=self.payload)
        logging.info("IDCODE Payload: %s", self.payload_bytes)

    def parse_stat(self):
        logging.info("STAT info - ")
        self.payload_bytes = BitArray(bytes=self.bayload).int
        
        BUS_WIDTH       = self.payload_bytes >> 25 & 0x3
        STARTUP_STATE   = self.payload_bytes >> 18 & 0x3
        DEC_ERROR       = self.payload_bytes >> 16 & 0x1
        ID_ERROR        = self.payload_bytes >> 15 & 0x1
        DONE            = self.payload_bytes >> 14 & 0x1
        RELEASE_DONE    = self.payload_bytes >> 13 & 0x1
        INIT_B          = self.payload_bytes >> 12 & 0x1
        INIT_COMPLETE   = self.payload_bytes >> 11 & 0x1
        MODE            = self.payload_bytes >>  8 & 0x7
        GHIGH_B         = self.payload_bytes >>  7 & 0x1
        GWE             = self.payload_bytes >>  6 & 0x1
        GTS_CFG_B       = self.payload_bytes >>  5 & 0x1
        EOS             = self.payload_bytes >>  4 & 0x1
        DCI_MATCH       = self.payload_bytes >>  3 & 0x1
        MMCM_LOCK       = self.payload_bytes >>  2 & 0x1
        PART_SECURED    = self.payload_bytes >>  1 & 0x1
        CRC_ERROR       = self.payload_bytes       & 0x0

        logging.info("STAT Configuration: \n\
            BUS_WIDTH: %d \n\
            STARTUP_STATE: %d \n\
            DEC_ERROR: %d \n\
            ID_ERROR: %d \n\
            DONE: %d \n\
            RELEASE_DONE: %d\n\
            INIT_B: %d \n\
            INIT_COMPLETE: %d \n\
            MODE: %d \n\
            GHIGH_B: %d\n\
            GWE: %d\n\
            GTS_CFG_B: %d\n\
            EOS: %d\n\
            DCI_MATCH: %d\n\
            MMCM_LOCK: %d\n\
            PART_SECURED: %d\n\
            CRC_ERROR: %d\n", BUS_WIDTH,STARTUP_STATE,DEC_ERROR,ID_ERROR,DONE,
                              RELEASE_DONE,INIT_B,INIT_COMPLETE,MODE,GHIGH_B,
                              GWE,GTS_CFG_B,EOS,DCI_MATCH,MMCM_LOCK,PART_SECURED,CRC_ERROR)


    def parse_CBC(self):
        logging.info("CBC info -")
        self.payload_bytes = BitArray(bytes=self.payload).bin
        import binascii
        CBC_IV = BitArray(bin=self.payload_bytes[:(16 * 8)]).hex
        self.CBC_IV = self.payload 

        logging.info("CBC IV: %s", CBC_IV)
        return

    def parse_DWC(self):
        logging.info("DWC info -")  
        self.payload_bytes = BitArray(bytes=self.payload)
        DWC = self.payload_bytes.int
        logging.info("Decrypted Word Count: %d", DWC)
        return

    def log(self):
        pass
