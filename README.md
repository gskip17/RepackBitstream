# Repackage Bitstream

```

$ python3 Repackage.py -h
usage: Repackage.py [-h] [--output OUTPUT] [--keyfile KEYFILE]
                    [--decrypt DECRYPT] [--repack REPACK]
                    BITFILE

Decrypt and Repackage Encrypted BASYS3 Bitstreams.

positional arguments:
  BITFILE               Input bit file name

optional arguments:
  -h, --help            show this help message and exit
  --output OUTPUT, -o OUTPUT
                        Output bin file name
  --keyfile KEYFILE, -k KEYFILE
                        Input .nky keyfile name
  --decrypt DECRYPT, -D DECRYPT
                        Decrypt bitstream
  --repack REPACK, -R REPACK
                        Repackage Bitstream with <param> binary file

```

```
# Program device using xc3sprog
JTAG_DEBUG=jtag_output.txt FTDI_DEBUG=usb_traffic.txt xc3sprog -c nexys4 -p 0 mod.bit
```

1) Call `Python3 Repackage.py <bitstream> -D True -k <path to .nky file>`

This will decrypt the encrypted bitstream file and output a `temp_decrypted.bin`.

`temp_decrypted.bin` can be modified and later repackaged into the encrypted format.

`-k` flag requires a .nky keyfile to perform decryption properly.


2) Call `python3 Repackage.py <encrypted bitstream> -R <path to modified payload> -k <path to key file>`

Example `python3 Repackage.py enc.bit -R temp_decrypted.bin -k key.nky`

This will generate a new bitstream that is reencrypted with the modified .bin content and produce a bitstream called `mod.bit`.
