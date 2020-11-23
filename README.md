# Repackage Bitstream

1) 

Call `Python3 Repackage.py <bitstream> -D True -k <path to .nky file>`

This will decrypt the encrypted bitstream file and output a `temp_decrypted.bin`.

`temp_decrypted.bin` can be modified and later repackaged into the encrypted format.

`-k` flag requires a .nky keyfile to perform decryption properly.

2)

Call `python3 Repackage.py <encrypted bitstream> -R <path to modified payload> -k <path to key file>`

Example `python3 Repackage.py enc.bit -R temp_decrypted.bin -k key.nky`

This will generate a new bitstream that is reencrypted with the modified .bin content and produce a bitstream called `mod.bit`.
